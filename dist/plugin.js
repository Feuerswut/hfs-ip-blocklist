exports.version = 0.1
exports.description = "Block requests based on IP blocklist with partitioned storage and LRU caching"
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
        options: ['url', 'file'],
        label: "Blocklist Source"
    },
    url: { 
        type: 'string', 
        defaultValue: '',
        label: "Blocklist URL",
        helperText: "URL to download blocklist from"
    },
    filePath: { 
        type: 'string', 
        defaultValue: '',
        label: "Blocklist File Path",
        helperText: "Local file path for blocklist"
    },
    refreshInterval: { 
        type: 'number', 
        defaultValue: 3600,
        min: 60,
        label: "Refresh Interval (seconds)",
        helperText: "How often to check for updates"
    },
    usePartitions: { 
        type: 'boolean', 
        defaultValue: true,
        label: "Use Partitioned Storage",
        helperText: "If false, keeps entire list in memory"
    },
    hotPartitionPercent: { 
        type: 'number', 
        defaultValue: 20,
        min: 1,
        max: 50,
        label: "Hot Partition %",
        helperText: "Percentage of partitions to keep in memory (1-50%)"
    },
    compressInMemory: { 
        type: 'boolean', 
        defaultValue: false,
        label: "Compress in Memory",
        helperText: "Use zstd compression for in-memory partitions"
    },
}

exports.init = api => {
    const storageDir = api.getPluginPath() + '/storage'
    if (!fs.existsSync(storageDir)) fs.mkdirSync(storageDir, { recursive: true })

    let blockList = new Set() // For non-partitioned mode
    let partitionIndex = null // B-tree index for partitioned mode
    let currentHash = null
    let refreshTimer = null

    const {disconnect} = api.require('./connections')

    // Local LAN ranges to exclude
    const LOCAL_RANGES = [
        { start: ip2long('10.0.0.0'), end: ip2long('10.255.255.255') },
        { start: ip2long('172.16.0.0'), end: ip2long('172.31.255.255') },
        { start: ip2long('192.168.0.0'), end: ip2long('192.168.255.255') },
        { start: ip2long('127.0.0.0'), end: ip2long('127.255.255.255') },
        { start: ip2long('169.254.0.0'), end: ip2long('169.254.255.255') },
        { start: ip2long('::1'), end: ip2long('::1'), ipv6: true },
        { start: ip2long('fe80::'), end: ip2long('fe80:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), ipv6: true },
        { start: ip2long('fc00::'), end: ip2long('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), ipv6: true },
    ]

    // IP conversion utilities
    function ip2long(ip) {
        if (ip.includes(':')) {
            // IPv6
            const parts = expandIPv6(ip).split(':')
            return parts.map(p => parseInt(p, 16))
        } else {
            // IPv4
            const parts = ip.split('.')
            return parts.reduce((acc, octet) => (acc << 8) + parseInt(octet), 0) >>> 0
        }
    }

    function expandIPv6(ip) {
        if (ip.includes('::')) {
            const sides = ip.split('::')
            const left = sides[0] ? sides[0].split(':') : []
            const right = sides[1] ? sides[1].split(':') : []
            const missing = 8 - left.length - right.length
            const middle = Array(missing).fill('0')
            return [...left, ...middle, ...right].map(p => p.padStart(4, '0')).join(':')
        }
        return ip.split(':').map(p => p.padStart(4, '0')).join(':')
    }

    function isIPv6(ip) {
        return ip.includes(':')
    }

    function isLocalIP(ip) {
        const ipLong = ip2long(ip)
        const ipv6 = isIPv6(ip)
        return LOCAL_RANGES.some(range => {
            if (range.ipv6 !== ipv6) return false
            if (ipv6) {
                return compareIPv6(ipLong, range.start) >= 0 && compareIPv6(ipLong, range.end) <= 0
            }
            return ipLong >= range.start && ipLong <= range.end
        })
    }

    function compareIPv6(a, b) {
        for (let i = 0; i < 8; i++) {
            if (a[i] !== b[i]) return a[i] - b[i]
        }
        return 0
    }

    function parseCIDR(cidr) {
        const [ip, bits] = cidr.split('/')
        const ipLong = ip2long(ip)
        const ipv6 = isIPv6(ip)
        
        if (ipv6) {
            const mask = parseInt(bits) || 128
            // Simplified IPv6 range calculation
            return { start: ipLong, end: ipLong, ipv6: true, cidr }
        } else {
            const mask = parseInt(bits) || 32
            const hostBits = 32 - mask
            const start = (ipLong >> hostBits) << hostBits
            const end = start + (Math.pow(2, hostBits) - 1)
            return { start, end, ipv6: false, cidr }
        }
    }

    function parseIPRange(line) {
        line = line.trim()
        if (!line || line.startsWith('#')) return null

        if (line.includes('/')) {
            return parseCIDR(line)
        } else if (line.includes('-')) {
            const [start, end] = line.split('-').map(s => s.trim())
            return { start: ip2long(start), end: ip2long(end), ipv6: isIPv6(start) }
        } else {
            const ipLong = ip2long(line)
            return { start: ipLong, end: ipLong, ipv6: isIPv6(line) }
        }
    }

    // B-Tree implementation
    class BTreeNode {
        constructor(isLeaf = true) {
            this.keys = []
            this.children = []
            this.isLeaf = isLeaf
            this.partition = null
        }
    }

    class BTree {
        constructor(degree = 5) {
            this.root = new BTreeNode()
            this.degree = degree
        }

        search(key) {
            return this._search(this.root, key)
        }

        _search(node, key) {
            let i = 0
            while (i < node.keys.length && key > node.keys[i]) i++
            
            if (i < node.keys.length && key === node.keys[i]) {
                return node.partition || (node.children[i] ? this._search(node.children[i], key) : null)
            }
            
            if (node.isLeaf) return null
            return this._search(node.children[i], key)
        }

        insert(key, partition) {
            const root = this.root
            if (root.keys.length === 2 * this.degree - 1) {
                const newRoot = new BTreeNode(false)
                newRoot.children.push(this.root)
                this._splitChild(newRoot, 0)
                this.root = newRoot
            }
            this._insertNonFull(this.root, key, partition)
        }

        _insertNonFull(node, key, partition) {
            let i = node.keys.length - 1
            
            if (node.isLeaf) {
                node.keys.push(key)
                node.keys.sort((a, b) => a - b)
                node.partition = partition
            } else {
                while (i >= 0 && key < node.keys[i]) i--
                i++
                if (node.children[i].keys.length === 2 * this.degree - 1) {
                    this._splitChild(node, i)
                    if (key > node.keys[i]) i++
                }
                this._insertNonFull(node.children[i], key, partition)
            }
        }

        _splitChild(parent, index) {
            const degree = this.degree
            const fullChild = parent.children[index]
            const newChild = new BTreeNode(fullChild.isLeaf)
            
            parent.keys.splice(index, 0, fullChild.keys[degree - 1])
            parent.children.splice(index + 1, 0, newChild)
            
            newChild.keys = fullChild.keys.splice(degree)
            if (!fullChild.isLeaf) {
                newChild.children = fullChild.children.splice(degree)
            }
        }
    }

    // Partition Manager with LRU cache
    class PartitionManager {
        constructor(maxHotPercent = 20) {
            this.partitions = new Map() // key -> Partition object
            this.btree = new BTree()
            this.lruCache = []
            this.maxHotSize = 0
            this.maxHotPercent = maxHotPercent
        }

        createPartitions(ipv4Ranges, ipv6Ranges) {
            api.log('Creating IPv4 partitions...')
            const ipv4Partitions = this._partitionByOctet(ipv4Ranges, 8) // /8 partitions
            
            api.log('Creating IPv6 partitions...')
            const ipv6Partitions = this._partitionByPrefix(ipv6Ranges, 32) // /32 partitions
            
            const allPartitions = [...ipv4Partitions, ...ipv6Partitions]
            this.maxHotSize = Math.max(1, Math.ceil(allPartitions.length * this.maxHotPercent / 100))
            
            api.log(`Created ${allPartitions.length} partitions, will keep ${this.maxHotSize} hot`)
            
            // Save partitions to disk and index
            allPartitions.forEach(p => this.savePartition(p))
        }

        _partitionByOctet(ranges, bits) {
            const partitionMap = new Map()
            
            ranges.forEach(range => {
                const startOctet = (range.start >> 24) & 0xFF
                const endOctet = (range.end >> 24) & 0xFF
                
                for (let octet = startOctet; octet <= endOctet; octet++) {
                    const key = `ipv4_${octet}`
                    if (!partitionMap.has(key)) {
                        partitionMap.set(key, { key, ranges: [], ipv6: false })
                    }
                    partitionMap.get(key).ranges.push(range)
                }
            })
            
            return Array.from(partitionMap.values())
        }

        _partitionByPrefix(ranges, bits) {
            const partitionMap = new Map()
            
            ranges.forEach(range => {
                // Use first two hextets as partition key
                const key = `ipv6_${range.start[0]}_${range.start[1]}`
                if (!partitionMap.has(key)) {
                    partitionMap.set(key, { key, ranges: [], ipv6: true })
                }
                partitionMap.get(key).ranges.push(range)
            })
            
            return Array.from(partitionMap.values())
        }

        savePartition(partition) {
            const data = JSON.stringify(partition.ranges)
            const compressed = zlib.deflateSync(data)
            const filePath = path.join(storageDir, `${partition.key}.zst`)
            fs.writeFileSync(filePath, compressed)
            
            this.partitions.set(partition.key, {
                key: partition.key,
                filePath,
                inMemory: false,
                data: null,
                ipv6: partition.ipv6
            })
            
            // Add to B-tree index
            const indexKey = partition.ipv6 ? partition.key : parseInt(partition.key.split('_')[1])
            this.btree.insert(indexKey, partition.key)
        }

        loadPartition(key) {
            const partition = this.partitions.get(key)
            if (!partition) return null
            
            if (partition.inMemory) {
                // Update LRU
                this.lruCache = this.lruCache.filter(k => k !== key)
                this.lruCache.push(key)
                return this._getPartitionData(partition)
            }
            
            // Load from disk
            const compressed = fs.readFileSync(partition.filePath)
            const data = JSON.parse(zlib.inflateSync(compressed).toString())
            
            // Store in memory
            if (api.getConfig().compressInMemory) {
                partition.data = compressed
            } else {
                partition.data = data
            }
            partition.inMemory = true
            
            // Manage LRU cache
            this.lruCache.push(key)
            if (this.lruCache.length > this.maxHotSize) {
                const evictKey = this.lruCache.shift()
                const evictPartition = this.partitions.get(evictKey)
                if (evictPartition) {
                    evictPartition.inMemory = false
                    evictPartition.data = null
                }
            }
            
            return data
        }

        _getPartitionData(partition) {
            if (api.getConfig().compressInMemory) {
                return JSON.parse(zlib.inflateSync(partition.data).toString())
            }
            return partition.data
        }

        findPartitionKey(ip) {
            if (isIPv6(ip)) {
                const ipLong = ip2long(ip)
                const key = `ipv6_${ipLong[0]}_${ipLong[1]}`
                return this.partitions.has(key) ? key : null
            } else {
                const ipLong = ip2long(ip)
                const octet = (ipLong >> 24) & 0xFF
                const key = `ipv4_${octet}`
                return this.partitions.has(key) ? key : null
            }
        }

        checkIP(ip) {
            const key = this.findPartitionKey(ip)
            if (!key) return false
            
            const ranges = this.loadPartition(key)
            if (!ranges) return false
            
            const ipLong = ip2long(ip)
            const ipv6 = isIPv6(ip)
            
            return ranges.some(range => {
                if (ipv6) {
                    return compareIPv6(ipLong, range.start) >= 0 && compareIPv6(ipLong, range.end) <= 0
                }
                return ipLong >= range.start && ipLong <= range.end
            })
        }
    }

    let partitionManager = null

    // Download/load blocklist
    async function loadBlocklist() {
        try {
            const config = api.getConfig()
            let content = ''
            
            if (config.source === 'url') {
                api.log(`Downloading blocklist from ${config.url}`)
                content = await downloadFile(config.url)
            } else {
                api.log(`Loading blocklist from ${config.filePath}`)
                content = fs.readFileSync(config.filePath, 'utf8')
            }
            
            // Check hash
            const hash = crypto.createHash('sha256').update(content).digest('hex')
            if (hash === currentHash) {
                api.log('Blocklist unchanged, skipping update')
                return
            }
            
            api.log('Blocklist changed, processing...')
            currentHash = hash
            
            // Parse entries
            const lines = content.split('\n')
            const ipv4Ranges = []
            const ipv6Ranges = []
            let skipped = 0
            
            for (const line of lines) {
                const range = parseIPRange(line)
                if (!range) continue
                
                // Check if local range
                const testIP = range.ipv6 ? '::1' : '127.0.0.1' // dummy for type check
                if (isLocalIP(testIP)) {
                    // More precise local check
                    const isLocal = LOCAL_RANGES.some(local => {
                        if (local.ipv6 !== range.ipv6) return false
                        if (range.ipv6) {
                            return (compareIPv6(range.start, local.start) >= 0 && compareIPv6(range.end, local.end) <= 0) ||
                                   (compareIPv6(range.start, local.start) <= 0 && compareIPv6(range.end, local.end) >= 0)
                        }
                        return (range.start >= local.start && range.end <= local.end) ||
                               (range.start <= local.start && range.end >= local.end)
                    })
                    
                    if (isLocal) {
                        skipped++
                        continue
                    }
                }
                
                if (range.ipv6) {
                    ipv6Ranges.push(range)
                } else {
                    ipv4Ranges.push(range)
                }
            }
            
            api.log(`Parsed ${ipv4Ranges.length} IPv4 and ${ipv6Ranges.length} IPv6 ranges (skipped ${skipped} local)`)
            
            // Sort descending
            ipv4Ranges.sort((a, b) => b.start - a.start)
            ipv6Ranges.sort((a, b) => compareIPv6(b.start, a.start))
            
            if (config.usePartitions) {
                // Create partitioned storage
                partitionManager = new PartitionManager(config.hotPartitionPercent)
                partitionManager.createPartitions(ipv4Ranges, ipv6Ranges)
                blockList.clear()
                api.log('Partitioned storage ready')
            } else {
                // Simple in-memory mode
                blockList.clear()
                ipv4Ranges.forEach(r => blockList.add(JSON.stringify(r)))
                ipv6Ranges.forEach(r => blockList.add(JSON.stringify(r)))
                partitionManager = null
                api.log(`Loaded ${blockList.size} entries in memory`)
            }
            
        } catch (error) {
            api.log(`Error loading blocklist: ${error.message}`)
        }
    }

    function downloadFile(url) {
        return new Promise((resolve, reject) => {
            const client = url.startsWith('https') ? https : http
            client.get(url, (res) => {
                if (res.statusCode !== 200) {
                    reject(new Error(`HTTP ${res.statusCode}`))
                    return
                }
                
                let data = ''
                res.on('data', chunk => data += chunk)
                res.on('end', () => resolve(data))
            }).on('error', reject)
        })
    }

    function isBlocked(ip) {
        if (isLocalIP(ip)) return false
        
        if (partitionManager) {
            return partitionManager.checkIP(ip)
        } else {
            // Simple mode: check all ranges
            const ipLong = ip2long(ip)
            const ipv6 = isIPv6(ip)
            
            for (const entry of blockList) {
                const range = JSON.parse(entry)
                if (range.ipv6 !== ipv6) continue
                
                if (ipv6) {
                    if (compareIPv6(ipLong, range.start) >= 0 && compareIPv6(ipLong, range.end) <= 0) {
                        return true
                    }
                } else {
                    if (ipLong >= range.start && ipLong <= range.end) {
                        return true
                    }
                }
            }
            return false
        }
    }

    // Initialize
    api.subscribeConfig('*', async () => {
        const config = api.getConfig()
        
        // Clear existing timer
        if (refreshTimer) {
            clearInterval(refreshTimer)
            refreshTimer = null
        }
        
        // Load blocklist
        await loadBlocklist()
        
        // Set up refresh timer
        if (config.refreshInterval > 0) {
            refreshTimer = setInterval(loadBlocklist, config.refreshInterval * 1000)
        }
    })

    // Initial load
    loadBlocklist()

    return {
        // CRITICAL: Use frontend_middleware for highest precedence
        frontend_middleware(ctx) {
            const ip = ctx.ip
            
            if (isBlocked(ip)) {
                api.log(`BLOCKED: ${ip}`)
                disconnect(ctx, 'IP blocklist')
                ctx.status = 403
                ctx.body = 'Forbidden'
                return true // Stop processing
            }
        },
        
        unload() {
            if (refreshTimer) {
                clearInterval(refreshTimer)
            }
            api.log('IP Blocker unloaded')
        }
    }
}

exports.configDialog = { 
    maxWidth: 'lg',
    sx: { '& .MuiTextField-root': { mb: 2 } }
}
