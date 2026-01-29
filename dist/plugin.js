exports.version = 0.3
exports.description = "Block requests based on IP blocklist"
exports.apiRequired = 4
exports.repo = "Feuerswut/hfs-ip-blocklist"
exports.author = "Feuerswut"

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const https = require('https')
const http = require('http')
const zlib = require('zlib')

exports.config = {
    source: { 
        type: 'select', 
        defaultValue: 'url',
        options: { 'URL': 'url', 'File': 'file' },
        label: "Blocklist Source"
    },
    url: { 
        type: 'string', 
        defaultValue: '',
        label: "Blocklist URL"
    },
    filePath: { 
        type: 'string', 
        defaultValue: '',
        label: "Blocklist File Path"
    },
    refreshInterval: { 
        type: 'number', 
        defaultValue: 3600,
        min: 60,
        label: "Refresh Interval (seconds)"
    },
    partitionBits: {
        type: 'number',
        defaultValue: 16,
        min: 8,
        max: 24,
        label: "IPv4 Partition Bits",
        helperText: "/16 = 65k partitions (recommended for 40M+ rules), /24 = 16M partitions"
    },
    maxCachePartitions: {
        type: 'number',
        defaultValue: 1000,
        min: 10,
        max: 10000,
        label: "Max Cached Partitions",
        helperText: "Number of partitions to keep in memory"
    },
    useBloomFilter: {
        type: 'boolean',
        defaultValue: true,
        label: "Use Bloom Filter",
        helperText: "Fast pre-check (highly recommended for large lists)"
    },
    mergeRanges: {
        type: 'boolean',
        defaultValue: true,
        label: "Merge Overlapping Ranges",
        helperText: "Combine adjacent/overlapping ranges (reduces size)"
    },
    enableSoftFail: {
        type: 'boolean',
        defaultValue: true,
        label: "Enable Soft Fail"
    },
    softFailTimeout: {
        type: 'number',
        defaultValue: 50,
        min: 5,
        max: 500,
        label: "Soft Fail Timeout (ms)"
    },
    logBlocked: {
        type: 'boolean',
        defaultValue: false,
        label: "Log Blocked IPs"
    },
    logCacheMisses: {
        type: 'boolean',
        defaultValue: false,
        label: "Log Cache Misses"
    },
    logSoftFails: {
        type: 'boolean',
        defaultValue: false,
        label: "Log Soft Fails"
    },
    logStats: {
        type: 'boolean',
        defaultValue: true,
        label: "Log Statistics",
        helperText: "Log performance stats on load/unload"
    }
}

exports.init = api => {
    const storageDir = api.storageDir
    if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true })

    let isReady = false
    let refreshTimer = null
    let bloomFilter = null
    let partitionManager = null
    let stats = { checks: 0, hits: 0, misses: 0, softFails: 0, errors: 0 }

    const { disconnect } = api.require('./connections')

    // Bloom Filter implementation (very fast probabilistic check)
    class BloomFilter {
        constructor(size = 10000000, hashCount = 7) {
            this.size = size
            this.hashCount = hashCount
            this.bits = new Uint8Array(Math.ceil(size / 8))
        }

        _hash(str, seed) {
            let h = seed
            for (let i = 0; i < str.length; i++) {
                h = Math.imul(h ^ str.charCodeAt(i), 2654435761)
            }
            return ((h ^ (h >>> 16)) >>> 0) % this.size
        }

        add(item) {
            for (let i = 0; i < this.hashCount; i++) {
                const pos = this._hash(item, i)
                const bytePos = Math.floor(pos / 8)
                const bitPos = pos % 8
                this.bits[bytePos] |= (1 << bitPos)
            }
        }

        test(item) {
            for (let i = 0; i < this.hashCount; i++) {
                const pos = this._hash(item, i)
                const bytePos = Math.floor(pos / 8)
                const bitPos = pos % 8
                if (!(this.bits[bytePos] & (1 << bitPos))) {
                    return false // Definitely not in set
                }
            }
            return true // Probably in set
        }

        save(filePath) {
            const header = Buffer.alloc(8)
            header.writeUInt32LE(this.size, 0)
            header.writeUInt32LE(this.hashCount, 4)
            fs.writeFileSync(filePath, Buffer.concat([header, this.bits]))
        }

        static load(filePath) {
            const data = fs.readFileSync(filePath)
            const size = data.readUInt32LE(0)
            const hashCount = data.readUInt32LE(4)
            const bf = new BloomFilter(size, hashCount)
            bf.bits = new Uint8Array(data.buffer, data.byteOffset + 8)
            return bf
        }
    }

    // Binary format for fast partition storage (much faster than JSON)
    class BinaryPartition {
        static encode(ranges) {
            // Each range: start(4) + end(4) = 8 bytes for IPv4
            const buffer = Buffer.allocUnsafe(ranges.length * 8)
            let offset = 0
            for (const range of ranges) {
                buffer.writeUInt32BE(range.start, offset)
                buffer.writeUInt32BE(range.end, offset + 4)
                offset += 8
            }
            return buffer
        }

        static decode(buffer) {
            const ranges = []
            for (let i = 0; i < buffer.length; i += 8) {
                ranges.push({
                    start: buffer.readUInt32BE(i),
                    end: buffer.readUInt32BE(i + 4)
                })
            }
            return ranges
        }
    }

    // Merge overlapping/adjacent ranges
    function mergeRanges(ranges) {
        if (ranges.length === 0) return []
        
        ranges.sort((a, b) => a.start - b.start)
        const merged = [ranges[0]]
        
        for (let i = 1; i < ranges.length; i++) {
            const current = ranges[i]
            const last = merged[merged.length - 1]
            
            // Check if overlapping or adjacent
            if (current.start <= last.end + 1) {
                last.end = Math.max(last.end, current.end)
            } else {
                merged.push(current)
            }
        }
        
        return merged
    }

    // Fast IP conversion (no IPv6 overhead if not needed)
    function ip2long(ip) {
        const parts = ip.split('.')
        if (parts.length === 4) {
            return ((+parts[0] << 24) | (+parts[1] << 16) | (+parts[2] << 8) | +parts[3]) >>> 0
        }
        return null // Skip IPv6 for now, add later if needed
    }

    function isLocalIP(ipLong) {
        return (
            (ipLong >= 0x0A000000 && ipLong <= 0x0AFFFFFF) || // 10.0.0.0/8
            (ipLong >= 0xAC100000 && ipLong <= 0xAC1FFFFF) || // 172.16.0.0/12
            (ipLong >= 0xC0A80000 && ipLong <= 0xC0A8FFFF) || // 192.168.0.0/16
            (ipLong >= 0x7F000000 && ipLong <= 0x7FFFFFFF) || // 127.0.0.0/8
            (ipLong >= 0xA9FE0000 && ipLong <= 0xA9FEFFFF)    // 169.254.0.0/16
        )
    }

    function parseIPRange(line) {
        line = line.trim()
        if (!line || line.startsWith('#')) return null

        try {
            if (line.includes('/')) {
                const [ip, bits] = line.split('/')
                if (ip.includes(':')) return null // Skip IPv6 for now
                const ipLong = ip2long(ip)
                if (!ipLong) return null
                const mask = parseInt(bits) || 32
                const hostBits = 32 - mask
                const start = (ipLong >> hostBits) << hostBits
                const end = start + (Math.pow(2, hostBits) - 1)
                return { start, end }
            } else if (line.includes('-')) {
                const [startIP, endIP] = line.split('-').map(s => s.trim())
                if (startIP.includes(':')) return null
                const start = ip2long(startIP)
                const end = ip2long(endIP)
                if (!start || !end) return null
                return { start, end }
            } else {
                if (line.includes(':')) return null
                const ipLong = ip2long(line)
                if (!ipLong) return null
                return { start: ipLong, end: ipLong }
            }
        } catch (e) {
            return null
        }
    }

    // Ultra-fast binary search (inlined for performance)
    function binarySearch(ranges, ip) {
        let left = 0
        let right = ranges.length - 1
        
        while (left <= right) {
            const mid = (left + right) >>> 1
            const range = ranges[mid]
            
            if (ip >= range.start && ip <= range.end) return true
            if (ip < range.start) right = mid - 1
            else left = mid + 1
        }
        
        return false
    }

    // Optimized partition manager
    class PartitionManager {
        constructor(partitionBits, maxCache) {
            this.partitionBits = partitionBits
            this.shiftBits = 32 - partitionBits
            this.maxCache = maxCache
            this.partitions = new Map()
            this.cache = new Map()
            this.lru = []
        }

        getPartitionKey(ipLong) {
            return ipLong >>> this.shiftBits
        }

        createPartitions(ranges) {
            const partitionMap = new Map()
            const config = api.getConfig()
            
            api.log(`Creating partitions with /${this.partitionBits} prefix...`)
            
            // Merge ranges first if enabled
            let processedRanges = ranges
            if (config.mergeRanges) {
                const before = ranges.length
                processedRanges = mergeRanges(ranges)
                api.log(`Merged ${before} ranges into ${processedRanges.length} (${((1 - processedRanges.length/before) * 100).toFixed(1)}% reduction)`)
            }
            
            // Distribute ranges to partitions
            for (const range of processedRanges) {
                const startKey = this.getPartitionKey(range.start)
                const endKey = this.getPartitionKey(range.end)
                
                for (let key = startKey; key <= endKey; key++) {
                    if (!partitionMap.has(key)) {
                        partitionMap.set(key, [])
                    }
                    partitionMap.get(key).push(range)
                }
            }
            
            api.log(`Created ${partitionMap.size} partitions`)
            
            // Save partitions
            let totalRanges = 0
            for (const [key, ranges] of partitionMap) {
                const sorted = ranges.sort((a, b) => a.start - b.start)
                const binary = BinaryPartition.encode(sorted)
                const compressed = zlib.deflateSync(binary)
                const filePath = path.join(storageDir, `p_${key}.bin`)
                fs.writeFileSync(filePath, compressed)
                
                this.partitions.set(key, {
                    key,
                    filePath,
                    count: sorted.length,
                    size: compressed.length
                })
                totalRanges += sorted.length
            }
            
            const avgPerPartition = (totalRanges / partitionMap.size).toFixed(0)
            api.log(`Average ${avgPerPartition} ranges per partition`)
        }

        loadPartition(key) {
            // Check cache first
            if (this.cache.has(key)) {
                // Update LRU
                this.lru = this.lru.filter(k => k !== key)
                this.lru.push(key)
                return this.cache.get(key)
            }
            
            // Cache miss
            const partition = this.partitions.get(key)
            if (!partition) return null
            
            if (api.getConfig().logCacheMisses) {
                api.log(`Cache miss: partition ${key}`)
            }
            
            // Load from disk
            const compressed = fs.readFileSync(partition.filePath)
            const binary = zlib.inflateSync(compressed)
            const ranges = BinaryPartition.decode(binary)
            
            // Add to cache
            this.cache.set(key, ranges)
            this.lru.push(key)
            
            // Evict old entries if cache is full
            while (this.lru.length > this.maxCache) {
                const evictKey = this.lru.shift()
                this.cache.delete(evictKey)
            }
            
            return ranges
        }

        checkIP(ipLong) {
            const key = this.getPartitionKey(ipLong)
            const ranges = this.loadPartition(key)
            if (!ranges) return false
            return binarySearch(ranges, ipLong)
        }

        getStats() {
            return {
                totalPartitions: this.partitions.size,
                cachedPartitions: this.cache.size,
                cacheSize: this.lru.length
            }
        }

        cleanup() {
            this.cache.clear()
            this.lru = []
        }
    }

    // Download/load blocklist
    async function loadBlocklist() {
        try {
            const config = api.getConfig()
            let content = ''
            
            if (config.source === 'url') {
                if (!config.url) {
                    api.log('ERROR: No URL configured')
                    return
                }
                api.log(`Downloading blocklist from ${config.url}`)
                content = await downloadFile(config.url)
            } else {
                if (!config.filePath) {
                    api.log('ERROR: No file path configured')
                    return
                }
                api.log(`Loading blocklist from ${config.filePath}`)
                if (!fs.existsSync(config.filePath)) {
                    api.log(`ERROR: File not found: ${config.filePath}`)
                    return
                }
                content = fs.readFileSync(config.filePath, 'utf8')
            }
            
            // Check hash
            const hash = crypto.createHash('sha256').update(content).digest('hex')
            const hashFile = path.join(storageDir, 'blocklist.hash')
            let currentHash = null
            
            if (fs.existsSync(hashFile)) {
                currentHash = fs.readFileSync(hashFile, 'utf8')
            }
            
            if (hash === currentHash && bloomFilter && partitionManager) {
                api.log('Blocklist unchanged, using existing data')
                isReady = true
                return
            }
            
            api.log('Processing blocklist...')
            const startTime = Date.now()
            
            // Parse entries
            const lines = content.split('\n')
            const ranges = []
            let skipped = 0
            let processed = 0
            
            for (let i = 0; i < lines.length; i++) {
                if (i % 1000000 === 0 && i > 0) {
                    api.log(`Processed ${(i / 1000000).toFixed(1)}M lines...`)
                }
                
                const range = parseIPRange(lines[i])
                if (!range) {
                    skipped++
                    continue
                }
                
                // Skip local ranges
                if (isLocalIP(range.start) || isLocalIP(range.end)) {
                    skipped++
                    continue
                }
                
                ranges.push(range)
                processed++
            }
            
            const parseTime = ((Date.now() - startTime) / 1000).toFixed(1)
            api.log(`Parsed ${processed} ranges in ${parseTime}s (skipped ${skipped})`)
            
            if (ranges.length === 0) {
                api.log('ERROR: No valid ranges found')
                return
            }
            
            // Create bloom filter
            if (config.useBloomFilter) {
                api.log('Creating bloom filter...')
                const bfStart = Date.now()
                
                // Size based on number of ranges
                const bfSize = Math.max(1000000, ranges.length * 10)
                bloomFilter = new BloomFilter(bfSize, 7)
                
                // Add all IPs in ranges to bloom filter (sample for large ranges)
                for (const range of ranges) {
                    const rangeSize = range.end - range.start + 1
                    
                    if (rangeSize <= 256) {
                        // Small range: add all IPs
                        for (let ip = range.start; ip <= range.end; ip++) {
                            bloomFilter.add(ip.toString())
                        }
                    } else {
                        // Large range: add start, end, and samples
                        bloomFilter.add(range.start.toString())
                        bloomFilter.add(range.end.toString())
                        
                        // Add 10 samples
                        const step = Math.floor(rangeSize / 10)
                        for (let i = 1; i < 10; i++) {
                            bloomFilter.add((range.start + i * step).toString())
                        }
                    }
                }
                
                // Save bloom filter
                const bfPath = path.join(storageDir, 'bloom.bin')
                bloomFilter.save(bfPath)
                
                const bfTime = ((Date.now() - bfStart) / 1000).toFixed(1)
                const bfSizeMB = (fs.statSync(bfPath).size / 1024 / 1024).toFixed(1)
                api.log(`Bloom filter created in ${bfTime}s (${bfSizeMB} MB)`)
            }
            
            // Create partitions
            api.log('Creating partitions...')
            const pmStart = Date.now()
            
            partitionManager = new PartitionManager(config.partitionBits, config.maxCachePartitions)
            partitionManager.createPartitions(ranges)
            
            const pmTime = ((Date.now() - pmStart) / 1000).toFixed(1)
            api.log(`Partitions created in ${pmTime}s`)
            
            // Calculate total size
            let totalSize = 0
            for (const file of fs.readdirSync(storageDir)) {
                if (file.endsWith('.bin')) {
                    totalSize += fs.statSync(path.join(storageDir, file)).size
                }
            }
            const totalSizeMB = (totalSize / 1024 / 1024).toFixed(1)
            
            // Save hash
            fs.writeFileSync(hashFile, hash)
            
            const totalTime = ((Date.now() - startTime) / 1000).toFixed(1)
            
            if (config.logStats) {
                api.log(`=== BLOCKLIST LOADED ===`)
                api.log(`Total time: ${totalTime}s`)
                api.log(`Ranges: ${ranges.length.toLocaleString()}`)
                api.log(`Partitions: ${partitionManager.partitions.size}`)
                api.log(`Storage: ${totalSizeMB} MB`)
                api.log(`========================`)
            }
            
            // Mark as ready
            isReady = true
            api.log('Plugin READY')
            
        } catch (error) {
            api.log(`ERROR loading blocklist: ${error.message}`)
            api.log(error.stack)
            stats.errors++
        }
    }

    function downloadFile(url) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http
            const timeout = 300000 // 5 minutes
            
            const req = client.get(url, { timeout }, (res) => {
                if (res.statusCode === 301 || res.statusCode === 302) {
                    // Follow redirect
                    downloadFile(res.headers.location).then(resolve).catch(reject)
                    return
                }
                
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}`))
                    return
                }
                
                let data = ''
                res.on('data', chunk => data += chunk)
                res.on('end', () => resolve(data))
            })
            
            req.on('error', reject)
            req.on('timeout', () => {
                req.destroy()
                reject(new Error('Download timeout'))
            })
        })
    }

    // Fast IP check
    function isBlocked(ip) {
        const ipLong = ip2long(ip)
        if (!ipLong || isLocalIP(ipLong)) return false
        
        // Bloom filter fast path
        if (bloomFilter && !bloomFilter.test(ipLong.toString())) {
            return false // Definitely not blocked
        }
        
        // Check partition
        return partitionManager ? partitionManager.checkIP(ipLong) : false
    }

    // Async version with timeout
    async function isBlockedAsync(ip, timeout) {
        return new Promise((resolve) => {
            const timer = setTimeout(() => {
                resolve({ blocked: false, softFail: true })
            }, timeout)
            
            setImmediate(() => {
                try {
                    const blocked = isBlocked(ip)
                    clearTimeout(timer)
                    resolve({ blocked, softFail: false })
                } catch (error) {
                    clearTimeout(timer)
                    api.log(`ERROR checking IP ${ip}: ${error.message}`)
                    stats.errors++
                    resolve({ blocked: false, softFail: true, error: true })
                }
            })
        })
    }

    // Try to load existing data on startup
    async function loadExistingData() {
        try {
            const hashFile = path.join(storageDir, 'blocklist.hash')
            const bfPath = path.join(storageDir, 'bloom.bin')
            
            if (!fs.existsSync(hashFile)) {
                api.log('No existing data found')
                return false
            }
            
            const config = api.getConfig()
            
            // Load bloom filter
            if (config.useBloomFilter && fs.existsSync(bfPath)) {
                api.log('Loading existing bloom filter...')
                bloomFilter = BloomFilter.load(bfPath)
            }
            
            // Load partition index
            const partitionFiles = fs.readdirSync(storageDir).filter(f => f.startsWith('p_') && f.endsWith('.bin'))
            if (partitionFiles.length === 0) {
                api.log('No partition files found')
                return false
            }
            
            api.log(`Loading ${partitionFiles.length} existing partitions...`)
            partitionManager = new PartitionManager(config.partitionBits, config.maxCachePartitions)
            
            for (const file of partitionFiles) {
                const key = parseInt(file.match(/p_(\d+)\.bin/)[1])
                const filePath = path.join(storageDir, file)
                const stats = fs.statSync(filePath)
                
                partitionManager.partitions.set(key, {
                    key,
                    filePath,
                    size: stats.size
                })
            }
            
            api.log('Existing data loaded successfully')
            isReady = true
            return true
            
        } catch (error) {
            api.log(`ERROR loading existing data: ${error.message}`)
            return false
        }
    }

    // Initialize
    (async () => {
        // Try to load existing data first
        const hasExisting = await loadExistingData()
        
        // Set up config subscription
        api.subscribeConfig('*', async () => {
            const config = api.getConfig()
            
            if (refreshTimer) {
                clearInterval(refreshTimer)
                refreshTimer = null
            }
            
            if (!hasExisting || !isReady) {
                await loadBlocklist()
            }
            
            if (config.refreshInterval > 0) {
                refreshTimer = setInterval(() => {
                    loadBlocklist().catch(err => {
                        api.log(`ERROR in refresh: ${err.message}`)
                        stats.errors++
                    })
                }, config.refreshInterval * 1000)
            }
        })
    })()

    return {
        middleware: async (ctx) => {
            if (!isReady) {
                return // Allow request if not ready yet
            }
            
            stats.checks++
            const ip = ctx.ip
            const config = api.getConfig()
            
            try {
                if (config.enableSoftFail && config.softFailTimeout > 0) {
                    const { blocked, softFail, error } = await isBlockedAsync(ip, config.softFailTimeout)
                    
                    if (softFail) {
                        stats.softFails++
                        if (config.logSoftFails) {
                            api.log(`SOFT FAIL: ${ip}${error ? ' (error)' : ' (timeout)'}`)
                        }
                        return
                    }
                    
                    if (blocked) {
                        stats.hits++
                        if (config.logBlocked) {
                            api.log(`BLOCKED: ${ip}`)
                        }
                        disconnect(ctx, 'IP blocklist')
                        ctx.status = 403
                        ctx.body = 'Forbidden'
                        return ctx.stop()
                    }
                } else {
                    if (isBlocked(ip)) {
                        stats.hits++
                        if (config.logBlocked) {
                            api.log(`BLOCKED: ${ip}`)
                        }
                        disconnect(ctx, 'IP blocklist')
                        ctx.status = 403
                        ctx.body = 'Forbidden'
                        return ctx.stop()
                    }
                }
                
                stats.misses++
                
            } catch (error) {
                api.log(`ERROR in middleware: ${error.message}`)
                stats.errors++
            }
        },
        
        unload() {
            if (refreshTimer) {
                clearInterval(refreshTimer)
            }
            
            if (partitionManager) {
                partitionManager.cleanup()
            }
            
            const config = api.getConfig()
            if (config.logStats) {
                const hitRate = stats.checks > 0 ? (stats.hits / stats.checks * 100).toFixed(2) : '0.00'
                api.log(`=== FINAL STATS ===`)
                api.log(`Checks: ${stats.checks.toLocaleString()}`)
                api.log(`Blocked: ${stats.hits.toLocaleString()} (${hitRate}%)`)
                api.log(`Allowed: ${stats.misses.toLocaleString()}`)
                api.log(`Soft fails: ${stats.softFails.toLocaleString()}`)
                api.log(`Errors: ${stats.errors}`)
                if (partitionManager) {
                    const pmStats = partitionManager.getStats()
                    api.log(`Cache: ${pmStats.cachedPartitions}/${pmStats.totalPartitions}`)
                }
                api.log(`===================`)
            }
            
            api.log('IP Blocker unloaded')
        }
    }
}

exports.configDialog = { 
    maxWidth: 'lg',
    sx: { '& .MuiTextField-root': { mb: 2 } }
}
