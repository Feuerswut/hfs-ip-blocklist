// partition-manager.js (Partition Loading - Main Thread)
const fs = require('fs').promises
const fsSync = require('fs')
const path = require('path')
const zlib = require('zlib')
const utils = require('./utils')

class PartitionManager {
    constructor(storageDir, partitionBits, maxCache, debug) {
        this.storageDir = storageDir
        this.partitionBits = partitionBits
        this.shiftBits = 32 - partitionBits
        this.maxCache = maxCache
        this.debug = debug
        this.partitions = new Map()
        this.cache = new Map()
        this.lru = []
    }

    getPartitionKey(ipLong) {
        return ipLong >>> this.shiftBits
    }

    async loadIndex() {
        try {
            const files = await fs.readdir(this.storageDir)
            const partitionFiles = files.filter(f => f.startsWith('p_') && f.endsWith('.bin'))
            
            if (partitionFiles.length === 0) {
                return false
            }
            
            this.debug(`Loading index for ${partitionFiles.length} partitions...`)
            
            for (const file of partitionFiles) {
                const match = file.match(/p_(\d+)\.bin/)
                if (!match) continue
                
                const key = parseInt(match[1])
                const filePath = path.join(this.storageDir, file)
                const stats = await fs.stat(filePath)
                
                this.partitions.set(key, {
                    key,
                    filePath,
                    size: stats.size
                })
            }
            
            this.debug(`✓ Loaded index for ${this.partitions.size} partitions`)
            return true
            
        } catch (error) {
            this.debug(`Error loading index: ${error.message}`)
            return false
        }
    }

    async loadPartition(key) {
        // Check cache
        if (this.cache.has(key)) {
            // Update LRU
            this.lru = this.lru.filter(k => k !== key)
            this.lru.push(key)
            return this.cache.get(key)
        }
        
        // Get partition info
        const partition = this.partitions.get(key)
        if (!partition) {
            return null
        }
        
        try {
            // Load from disk
            const compressed = await fs.readFile(partition.filePath)
            const binary = zlib.inflateSync(compressed)
            
            // Decode ranges - MANUAL BYTE READING
            const ranges = []
            for (let i = 0; i < binary.length; i += 8) {
                // Manually read 4 bytes for start (Big Endian)
                const start = (
                    (binary.readUInt8(i) << 24) |
                    (binary.readUInt8(i + 1) << 16) |
                    (binary.readUInt8(i + 2) << 8) |
                    binary.readUInt8(i + 3)
                ) >>> 0
                
                // Manually read 4 bytes for end (Big Endian)
                const end = (
                    (binary.readUInt8(i + 4) << 24) |
                    (binary.readUInt8(i + 5) << 16) |
                    (binary.readUInt8(i + 6) << 8) |
                    binary.readUInt8(i + 7)
                ) >>> 0
                
                ranges.push({ start, end })
            }
            
            // Add to cache
            this.cache.set(key, ranges)
            this.lru.push(key)
            
            // Evict if cache full
            while (this.lru.length > this.maxCache) {
                const evictKey = this.lru.shift()
                this.cache.delete(evictKey)
            }
            
            return ranges
            
        } catch (error) {
            this.debug(`Error loading partition ${key}: ${error.message}`)
            return null
        }
    }

    async checkIP(ip) {
        try {
            const ipLong = utils.ip2long(ip)
            
            if (!ipLong) {
                return { blocked: false, error: 'Invalid IP' }
            }
            
            if (utils.isLocalIP(ipLong)) {
                return { blocked: false, local: true }
            }
            
            const key = this.getPartitionKey(ipLong)
            const ranges = await this.loadPartition(key)
            
            if (!ranges) {
                return { blocked: false, noPartition: true }
            }
            
            // Binary search
            let left = 0
            let right = ranges.length - 1
            
            while (left <= right) {
                const mid = (left + right) >>> 1
                const range = ranges[mid]
                
                if (ipLong >= range.start && ipLong <= range.end) {
                    return { blocked: true }
                }
                
                if (ipLong < range.start) {
                    right = mid - 1
                } else {
                    left = mid + 1
                }
            }
            
            return { blocked: false }
            
        } catch (error) {
            return { blocked: false, error: error.message }
        }
    }

    cleanup() {
        this.cache.clear()
        this.lru = []
    }

    getMemoryUsageMB() {
        let totalBytes = 0
        for (const ranges of this.cache.values()) {
            totalBytes += ranges.length * 16 // Approximate size per range object
        }
        return totalBytes / 1024 / 1024
    }
}

module.exports = PartitionManager
