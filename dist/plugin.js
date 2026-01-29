// plugin.js (Main)
exports.version = 0.4
exports.description = "Ultra lightweight request blocker based on an IP blocklist."
exports.apiRequired = 4
exports.repo = "Feuerswut/hfs-ip-blocklist"
exports.author = "Feuerswut"

const path = require('path')
const { Worker } = require('worker_threads')
const PartitionManager = require('./partition-manager')

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
        defaultValue: 86400,
        min: 3600,
        label: "Refresh Interval (seconds)"
    },
    partitionBits: {
        type: 'number',
        defaultValue: 12,
        min: 8,
        max: 16,
        label: "Partition Bits",
        helperText: "/12 = 4096 partitions (recommended for RPi)"
    },
    maxCachePartitions: {
        type: 'number',
        defaultValue: 50,
        min: 10,
        max: 200,
        label: "Max Cached Partitions"
    },
    requestTimeout: {
        type: 'number',
        defaultValue: 30,
        min: 5,
        max: 200,
        label: "Max Request Check Time (ms)"
    },
    minRangeSize: {
        type: 'number',
        defaultValue: 2,
        min: 1,
        max: 256,
        label: "Minimum Range Size"
    },
    ignoreSingleIPs: {
        type: 'boolean',
        defaultValue: true,
        label: "Ignore Single IPs",
        helperText: "Only block ranges (saves ~80% RAM)"
    },
    debugLog: {
        type: 'boolean',
        defaultValue: true,
        label: "Debug Logging"
    },
    logBlocked: {
        type: 'boolean',
        defaultValue: false,
        label: "Log Blocked IPs"
    }
}

exports.init = api => {
    let isReady = false
    let partitionManager = null
    let worker = null
    let refreshTimer = null
    let stats = { checks: 0, hits: 0, allowed: 0, timeouts: 0, errors: 0 }

    const { disconnect } = api.require('./connections')
    const storageDir = api.storageDir

    const debug = (...args) => {
        if (api.getConfig().debugLog) {
            api.log('[DEBUG]', ...args)
        }
    }

    // Fast IP check with timeout (main thread only does this)
    async function checkIPWithTimeout(ip, timeout) {
        return Promise.race([
            partitionManager.checkIP(ip),
            new Promise(resolve => setTimeout(() => resolve({ blocked: false, timeout: true }), timeout))
        ])
    }

    // Start worker for processing blocklist
    function startWorker() {
        const config = api.getConfig()
        
        if (worker) {
            debug('Terminating old worker...')
            worker.terminate()
        }

        debug('Starting worker thread...')
        
        worker = new Worker(path.join(__dirname, 'worker.js'), {
            workerData: {
                storageDir,
                config: {
                    source: config.source,
                    url: config.url,
                    filePath: config.filePath,
                    partitionBits: config.partitionBits,
                    minRangeSize: config.minRangeSize,
                    ignoreSingleIPs: config.ignoreSingleIPs
                }
            }
        })

        worker.on('message', async (msg) => {
            switch (msg.type) {
                case 'debug':
                    debug(msg.msg, msg.data || '')
                    break
                    
                case 'log':
                    api.log(msg.msg)
                    break
                    
                case 'progress':
                    debug(`[${msg.phase}] ${msg.percent}%`)
                    break
                    
                case 'ready':
                    debug('✓ Worker ready, loading partition index...')
                    isReady = false
                    
                    // Reload partition manager
                    partitionManager = new PartitionManager(
                        storageDir,
                        config.partitionBits,
                        config.maxCachePartitions,
                        debug
                    )
                    
                    const success = await partitionManager.loadIndex()
                    if (success) {
                        isReady = true
                        api.log(`✓ IP Blocklist READY (${msg.totalRanges} ranges, ${msg.partitionCount} partitions)`)
                        debug(`Memory: ${msg.memoryUsageMB}MB, Disk: ${msg.diskUsageMB}MB`)
                    } else {
                        api.log('✗ Failed to load partition index')
                    }
                    break
                    
                case 'error':
                    api.log(`✗ Worker error: ${msg.error}`)
                    stats.errors++
                    break
            }
        })

        worker.on('error', (error) => {
            api.log(`✗ Worker error: ${error.message}`)
            stats.errors++
        })

        worker.on('exit', (code) => {
            if (code !== 0) {
                debug(`Worker stopped with code ${code}`)
            }
        })
    }

    // Try to load existing data immediately
    async function loadExistingData() {
        const config = api.getConfig()
        
        partitionManager = new PartitionManager(
            storageDir,
            config.partitionBits,
            config.maxCachePartitions,
            debug
        )
        
        const success = await partitionManager.loadIndex()
        
        if (success) {
            isReady = true
            debug('✓ Loaded existing partition data')
            return true
        }
        
        debug('No existing data found, will wait for worker')
        return false
    }

    // Initialize
    (async () => {
        debug('Plugin initializing...')
        
        // Try to load existing data first (non-blocking)
        await loadExistingData()
        
        // Subscribe to config changes
        api.subscribeConfig('*', async () => {
            const config = api.getConfig()
            
            // Clear old timer
            if (refreshTimer) {
                clearInterval(refreshTimer)
                refreshTimer = null
            }
            
            // Start worker to process blocklist
            startWorker()
            
            // Set up refresh timer
            if (config.refreshInterval > 0) {
                refreshTimer = setInterval(() => {
                    debug('Auto-refresh triggered')
                    startWorker()
                }, config.refreshInterval * 1000)
            }
        })
    })()

    return {
        // Middleware - ONLY request handling (ultra-fast)
        middleware: async (ctx) => {
            stats.checks++
            
            // If not ready, allow request (fail open)
            if (!isReady || !partitionManager) {
                stats.allowed++
                return
            }
            
            const ip = ctx.ip
            const config = api.getConfig()
            
            try {
                const result = await checkIPWithTimeout(ip, config.requestTimeout)
                
                if (result.timeout) {
                    stats.timeouts++
                    debug(`Timeout checking ${ip}, allowing`)
                    return // Allow on timeout
                }
                
                if (result.error) {
                    stats.errors++
                    return // Allow on error
                }
                
                if (result.blocked) {
                    stats.hits++
                    if (config.logBlocked) {
                        api.log(`✗ BLOCKED: ${ip}`)
                    }
                    disconnect(ctx, 'IP blocklist')
                    ctx.status = 403
                    ctx.body = 'Forbidden'
                    return ctx.stop()
                }
                
                stats.allowed++
                
            } catch (error) {
                debug(`Error in middleware: ${error.message}`)
                stats.errors++
                // Allow on error
            }
        },
        
        unload() {
            debug('Unloading plugin...')
            
            if (refreshTimer) {
                clearInterval(refreshTimer)
            }
            
            if (worker) {
                worker.terminate()
            }
            
            if (partitionManager) {
                partitionManager.cleanup()
            }
            
            if (api.getConfig().debugLog) {
                const hitRate = stats.checks > 0 ? (stats.hits / stats.checks * 100).toFixed(2) : '0.00'
                const memMB = partitionManager ? partitionManager.getMemoryUsageMB() : 0
                
                api.log('=== IP BLOCKLIST STATS ===')
                api.log(`Checks: ${stats.checks.toLocaleString()}`)
                api.log(`Blocked: ${stats.hits.toLocaleString()} (${hitRate}%)`)
                api.log(`Allowed: ${stats.allowed.toLocaleString()}`)
                api.log(`Timeouts: ${stats.timeouts.toLocaleString()}`)
                api.log(`Errors: ${stats.errors}`)
                api.log(`Memory: ${memMB.toFixed(1)} MB`)
                api.log('==========================')
            }
        }
    }
}

exports.configDialog = { 
    maxWidth: 'lg',
    sx: { '& .MuiTextField-root': { mb: 2 } }
}
