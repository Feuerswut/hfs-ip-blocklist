// worker.js (Background Processing Thread)
const { parentPort, workerData } = require('worker_threads')
const fs = require('fs').promises
const fsSync = require('fs')
const path = require('path')
const crypto = require('crypto')
const zlib = require('zlib')
const utils = require('./utils')

const { storageDir, config } = workerData

function debug(msg, data = '') {
    parentPort.postMessage({ type: 'debug', msg, data })
}

function log(msg) {
    parentPort.postMessage({ type: 'log', msg })
}

function progress(phase, percent) {
    parentPort.postMessage({ type: 'progress', phase, percent })
}

async function processBlocklist() {
    try {
        debug('Worker started')
        const startTime = Date.now()
        
        // Download or load file
        progress('download', 0)
        let content = ''
        
        if (config.source === 'url') {
            if (!config.url) {
                throw new Error('No URL configured')
            }
            debug(`Downloading from ${config.url}`)
            content = await utils.downloadFile(config.url, (pct) => progress('download', pct))
        } else {
            if (!config.filePath) {
                throw new Error('No file path configured')
            }
            debug(`Loading from ${config.filePath}`)
            if (!fsSync.existsSync(config.filePath)) {
                throw new Error(`File not found: ${config.filePath}`)
            }
            content = await fs.readFile(config.filePath, 'utf8')
            progress('download', 100)
        }
        
        // Check if content changed
        const hash = crypto.createHash('sha256').update(content).digest('hex')
        const hashFile = path.join(storageDir, 'blocklist.hash')
        
        if (fsSync.existsSync(hashFile)) {
            const oldHash = await fs.readFile(hashFile, 'utf8')
            if (hash === oldHash) {
                debug('Content unchanged, skipping processing')
                const statsFile = path.join(storageDir, 'stats.json')
                if (fsSync.existsSync(statsFile)) {
                    const stats = JSON.parse(await fs.readFile(statsFile, 'utf8'))
                    parentPort.postMessage({ type: 'ready', ...stats })
                    return
                }
            }
        }
        
        // Parse ranges
        progress('parsing', 0)
        debug('Parsing blocklist...')
        
        const lines = content.split('\n')
        const ranges = []
        let skipped = 0
        let singleIPsIgnored = 0
        
        for (let i = 0; i < lines.length; i++) {
            if (i % 100000 === 0) {
                progress('parsing', Math.floor(i / lines.length * 100))
            }
            
            const range = utils.parseIPRange(lines[i])
            if (!range) {
                skipped++
                continue
            }
            
            // Skip local IPs
            if (utils.isLocalIP(range.start) || utils.isLocalIP(range.end)) {
                skipped++
                continue
            }
            
            const rangeSize = range.end - range.start + 1
            
            // Skip single IPs if configured
            if (config.ignoreSingleIPs && rangeSize === 1) {
                singleIPsIgnored++
                continue
            }
            
            // Skip ranges smaller than minimum
            if (rangeSize < config.minRangeSize) {
                skipped++
                continue
            }
            
            ranges.push(range)
        }
        
        progress('parsing', 100)
        debug(`Parsed ${ranges.length} ranges (skipped ${skipped}, ignored ${singleIPsIgnored} single IPs)`)
        
        if (ranges.length === 0) {
            throw new Error('No valid ranges found')
        }
        
        // Sort ranges
        progress('sorting', 0)
        debug('Sorting ranges...')
        ranges.sort((a, b) => a.start - b.start)
        progress('sorting', 100)
        
        // Merge overlapping ranges
        progress('merging', 0)
        debug('Merging overlapping ranges...')
        const merged = []
        merged.push(ranges[0])
        let mergedCount = 0
        
        for (let i = 1; i < ranges.length; i++) {
            if (i % 100000 === 0) {
                progress('merging', Math.floor(i / ranges.length * 100))
            }
            
            const current = ranges[i]
            const last = merged[merged.length - 1]
            
            if (current.start <= last.end + 1) {
                last.end = Math.max(last.end, current.end)
                mergedCount++
            } else {
                merged.push(current)
            }
        }
        
        progress('merging', 100)
        debug(`Merged ${mergedCount} ranges (${((mergedCount/ranges.length)*100).toFixed(1)}% reduction)`)
        debug(`Final range count: ${merged.length}`)
        
        // Create partitions
        progress('partitioning', 0)
        debug(`Creating partitions with /${config.partitionBits} prefix...`)
        
        const shiftBits = 32 - config.partitionBits
        const partitionMap = new Map()
        
        // Distribute ranges to partitions
        for (let i = 0; i < merged.length; i++) {
            if (i % 10000 === 0) {
                progress('partitioning', Math.floor(i / merged.length * 100))
            }
            
            const range = merged[i]
            const startKey = range.start >>> shiftBits
            const endKey = range.end >>> shiftBits
            
            for (let key = startKey; key <= endKey; key++) {
                if (!partitionMap.has(key)) {
                    partitionMap.set(key, [])
                }
                partitionMap.get(key).push(range)
            }
        }
        
        progress('partitioning', 100)
        debug(`Created ${partitionMap.size} partitions`)
        
        // Save partitions
        progress('saving', 0)
        debug('Saving partitions to disk...')
        
        // Clean old partitions
        const existingFiles = await fs.readdir(storageDir)
        for (const file of existingFiles) {
            if (file.startsWith('p_') && file.endsWith('.bin')) {
                await fs.unlink(path.join(storageDir, file))
            }
        }
        
        let totalDiskSize = 0
        let savedPartitions = 0
        const partitionKeys = Array.from(partitionMap.keys())
        
        for (let i = 0; i < partitionKeys.length; i++) {
            if (i % 100 === 0) {
                progress('saving', Math.floor(i / partitionKeys.length * 100))
            }
            
            const key = partitionKeys[i]
            const partitionRanges = partitionMap.get(key)
            
            // Sort ranges within partition
            partitionRanges.sort((a, b) => a.start - b.start)
            
            // Encode to binary
            const buffer = Buffer.allocUnsafe(partitionRanges.length * 8)
            let offset = 0
            for (const range of partitionRanges) {
                buffer.writeUInt32BE(range.start, offset)
                buffer.writeUInt32BE(range.end, offset + 4)
                offset += 8
            }
            
            // Compress
            const compressed = zlib.deflateSync(buffer, { level: 9 })
            
            // Save
            const filePath = path.join(storageDir, `p_${key}.bin`)
            await fs.writeFile(filePath, compressed)
            
            totalDiskSize += compressed.length
            savedPartitions++
        }
        
        progress('saving', 100)
        
        // Save hash
        await fs.writeFile(hashFile, hash)
        
        // Save stats
        const stats = {
            totalRanges: merged.length,
            partitionCount: savedPartitions,
            diskUsageMB: (totalDiskSize / 1024 / 1024).toFixed(2),
            memoryUsageMB: ((merged.length * 8) / 1024 / 1024).toFixed(2),
            processTime: ((Date.now() - startTime) / 1000).toFixed(1)
        }
        
        await fs.writeFile(
            path.join(storageDir, 'stats.json'),
            JSON.stringify(stats, null, 2)
        )
        
        debug(`Processing complete in ${stats.processTime}s`)
        debug(`Disk usage: ${stats.diskUsageMB} MB`)
        debug(`Estimated RAM: ${stats.memoryUsageMB} MB`)
        
        // Notify main thread
        parentPort.postMessage({ type: 'ready', ...stats })
        
    } catch (error) {
        parentPort.postMessage({ 
            type: 'error', 
            error: error.message,
            stack: error.stack 
        })
    }
}

// Start processing
processBlocklist()
