// utils.js (Utility Functions)
const https = require('https')
const http = require('http')

function ip2long(ip) {
    const parts = ip.split('.')
    if (parts.length !== 4) return null
    
    const nums = parts.map(p => parseInt(p))
    if (nums.some(n => isNaN(n) || n < 0 || n > 255)) return null
    
    return ((nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]) >>> 0
}

function isLocalIP(ipLong) {
    return (
        (ipLong >= 0x0A000000 && ipLong <= 0x0AFFFFFF) ||      // 10.0.0.0/8
        (ipLong >= 0xAC100000 && ipLong <= 0xAC1FFFFF) ||      // 172.16.0.0/12
        (ipLong >= 0xC0A80000 && ipLong <= 0xC0A8FFFF) ||      // 192.168.0.0/16
        (ipLong >= 0x7F000000 && ipLong <= 0x7FFFFFFF) ||      // 127.0.0.0/8
        (ipLong >= 0xA9FE0000 && ipLong <= 0xA9FEFFFF) ||      // 169.254.0.0/16
        ipLong === 0 ||                                         // 0.0.0.0
        (ipLong >= 0xE0000000 && ipLong <= 0xEFFFFFFF) ||      // 224.0.0.0/4 (multicast)
        (ipLong >= 0xF0000000 && ipLong <= 0xFFFFFFFF)         // 240.0.0.0/4 (reserved)
    )
}

function parseIPRange(line) {
    line = line.trim()
    
    // Skip empty lines and comments
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('//')) {
        return null
    }
    
    try {
        // CIDR notation (192.168.1.0/24)
        if (line.includes('/')) {
            const [ip, bits] = line.split('/')
            if (ip.includes(':')) return null // Skip IPv6
            
            const ipLong = ip2long(ip)
            if (!ipLong) return null
            
            const mask = parseInt(bits)
            if (isNaN(mask) || mask < 0 || mask > 32) return null
            
            const hostBits = 32 - mask
            const start = (ipLong >> hostBits) << hostBits
            const end = start + (Math.pow(2, hostBits) - 1)
            
            return { start, end }
        }
        
        // Range notation (192.168.1.1-192.168.1.255)
        if (line.includes('-')) {
            const [startIP, endIP] = line.split('-').map(s => s.trim())
            if (startIP.includes(':') || endIP.includes(':')) return null
            
            const start = ip2long(startIP)
            const end = ip2long(endIP)
            
            if (!start || !end || start > end) return null
            
            return { start, end }
        }
        
        // Single IP
        if (line.includes(':')) return null // Skip IPv6
        
        const ipLong = ip2long(line)
        if (!ipLong) return null
        
        return { start: ipLong, end: ipLong }
        
    } catch (e) {
        return null
    }
}

function downloadFile(url, onProgress) {
    return new Promise((resolve, reject) => {
        const client = url.startsWith('https') ? https : http
        
        const req = client.get(url, { timeout: 300000 }, (res) => {
            // Handle redirects
            if (res.statusCode === 301 || res.statusCode === 302) {
                downloadFile(res.headers.location, onProgress).then(resolve).catch(reject)
                return
            }
            
            if (res.statusCode !== 200) {
                reject(new Error(`HTTP ${res.statusCode}`))
                return
            }
            
            let data = ''
            let downloaded = 0
            const total = parseInt(res.headers['content-length']) || 0
            let lastPercent = 0
            
            res.on('data', chunk => {
                data += chunk
                downloaded += chunk.length
                
                if (total > 0) {
                    const percent = Math.floor(downloaded / total * 100)
                    if (percent > lastPercent && percent % 10 === 0) {
                        onProgress(percent)
                        lastPercent = percent
                    }
                }
            })
            
            res.on('end', () => {
                onProgress(100)
                resolve(data)
            })
        })
        
        req.on('error', reject)
        req.on('timeout', () => {
            req.destroy()
            reject(new Error('Download timeout'))
        })
    })
}

module.exports = {
    ip2long,
    isLocalIP,
    parseIPRange,
    downloadFile
}
