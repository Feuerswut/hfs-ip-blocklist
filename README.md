# HFS IP Blocklist
Ultra-lightweight IP blocklist plugin for HFS optimized for minimal systems.

Blocks malicious IP ranges using intelligent partitioning, compression, and LRU caching with minimal memory footprint.

## Summary

- Fast binary search IP lookups (milliseconds)
- Configurable partitioning for memory efficiency
- LRU cache for frequently accessed partitions
- Supports CIDR, IP ranges, and single IPs from URL or file
- Auto-refresh with smart change detection
- Runs in background worker thread - non-blocking
- Saves ~80% RAM when ignoring single IPs

## Configuration

| Option | Default | Description |
|--------|---------|-------------|
| Blocklist Source | url | URL or file path |
| Blocklist URL | - | Remote blocklist URL |
| Blocklist File Path | - | Local file path |
| Refresh Interval | 86400s | Auto-refresh interval (min 3600s) |
| Partition Bits | 12 | IP space division (8-16, /12 = 4,096 partitions) |
| Max Cached Partitions | 50 | Partitions in memory (10-200) |
| Max Request Check Time | 30ms | Timeout per check (5-200ms) |
| Minimum Range Size | 2 | Skip ranges smaller than N IPs |
| Ignore Single IPs | true | Skip single IPs (saves ~80% RAM) |
| Debug Logging | true | Enable debug output |
| Log Blocked IPs | false | Log each blocked request |

## How It Works

Blocklist is processed in a background worker thread: download/load -> parse IP ranges -> filter local IPs -> sort and merge overlapping ranges -> partition into 4,096+ segments -> compress with zlib -> save to disk.

On each request: extract client IP -> calculate partition key -> load partition from cache or disk -> binary search for IP match -> block or allow.

Storage structure uses compressed binary partition files (p_0.bin, p_1.bin, etc) with a SHA256 hash to skip redundant processing and stats.json for metrics.

## Formats Supported

Handles CIDR notation (192.0.2.0/24), IP ranges (192.0.2.1-192.0.2.255), single IPs (192.0.2.1). Ignores comments starting with #, ;, //.

Automatically skips local IP ranges: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16.

Should work with abuseipdb, Project Honey Pot, Spamhaus, and other standard IP blocklists.

---

**README Version**: for 0.5
