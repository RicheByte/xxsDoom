# 🔥 AGGRESSIVE MODE - Parallel XSS Scanner

## Overview
The XSS scanner now supports aggressive parallel scanning that works like having multiple people scanning simultaneously. This dramatically increases scanning speed by running multiple browser instances in parallel.

## Quick Start

### Basic Aggressive Mode (50 threads)
```bash
python xsscan.py -a https://example.com
```

### Ultra Aggressive Mode (100 threads)
```bash
python xsscan.py --ultra https://example.com
```

### INSANE Mode (200+ threads)
```bash
python xsscan.py --insane https://example.com
```

### Custom Thread Count
```bash
python xsscan.py --threads 75 https://example.com
```

## Modes Comparison

| Mode | Threads | Speed | Resource Usage | Use Case |
|------|---------|-------|----------------|----------|
| Standard | 1 | 1x | Low | Safe, stable scanning |
| Aggressive `-a` | 50 | ~50x | Medium | Fast scanning, modern systems |
| Ultra `--ultra` | 100 | ~100x | High | Very fast, powerful systems |
| INSANE `--insane` | 200+ | ~200x | Very High | Maximum speed, server-grade |
| Custom `--threads N` | N | ~Nx | Variable | Fine-tuned control |

## Features

### What Happens in Aggressive Mode?
- ✅ **Parallel URL Testing**: Each payload×parameter combination runs in its own thread
- ✅ **Browser Pool**: Reuses browser instances for efficiency
- ✅ **Thread-Safe Results**: Proper locking ensures no data corruption
- ✅ **Smart Delays**: Reduced delays between requests (5x faster)
- ✅ **Progress Tracking**: Real-time updates every 50 tasks

### What Stays Sequential?
- Form testing (requires session state)
- Initial setup and teardown
- Report generation

## Examples

### Scan with all payloads aggressively
```bash
python xsscan.py -a -c all https://target.com
```

### Ultra mode with verbose output
```bash
python xsscan.py --ultra -v https://target.com?search=test
```

### Custom 150 threads with advanced payloads
```bash
python xsscan.py --threads 150 -c advanced https://target.com
```

### INSANE mode for comprehensive scan
```bash
python xsscan.py --insane -c all --no-forms https://target.com
```

## Performance Tips

### System Requirements by Mode
- **Aggressive (50)**: 8GB RAM, 4+ CPU cores
- **Ultra (100)**: 16GB RAM, 8+ CPU cores
- **INSANE (200+)**: 32GB RAM, 16+ CPU cores

### Optimization Recommendations
1. **Headless mode** is enabled by default (faster)
2. **Disable images** in browser (already configured)
3. **Skip forms** with `--no-forms` if not needed
4. **Use basic payloads** first, then escalate
5. **Close other applications** during INSANE mode

### Monitoring Performance
Watch for:
- CPU usage (should be high, that's normal)
- Memory usage (shouldn't exceed available RAM)
- Network bandwidth (many concurrent connections)
- Progress updates in console

## Safety & Ethics

### ⚠️ WARNING
Aggressive modes generate MASSIVE amounts of traffic:
- **50 threads** = 50 simultaneous requests
- **100 threads** = 100 simultaneous requests
- **200 threads** = 200 simultaneous requests

### Use Responsibly
✅ **DO**:
- Use on your own systems
- Use with explicit permission
- Test in controlled environments
- Monitor system resources

❌ **DON'T**:
- Scan without authorization
- DDoS production systems
- Exceed your system's capabilities
- Violate terms of service

## Troubleshooting

### "Too many browser instances"
**Solution**: Reduce thread count
```bash
python xsscan.py --threads 25 https://target.com
```

### "Out of memory"
**Solution**: Use aggressive instead of ultra/insane
```bash
python xsscan.py -a https://target.com
```

### "ChromeDriver crashes"
**Solution**: Lower threads and add delays
```bash
python xsscan.py --threads 20 --delay 1.0 https://target.com
```

### Slow performance
**Possible causes**:
1. Network bottleneck (not system)
2. Target site rate limiting
3. Too few system resources

**Solution**: Monitor with Task Manager/htop and adjust threads

## Technical Details

### How It Works
1. **Task Queue**: Creates tasks for each payload×parameter combination
2. **Thread Pool**: `ThreadPoolExecutor` manages worker threads
3. **Browser Pool**: Reuses WebDriver instances across tasks
4. **Result Locking**: Thread-safe result collection
5. **Smart Cleanup**: Returns drivers to pool or closes excess

### Code Example
```python
from scanner import XSSScanner

# Create aggressive scanner
scanner = XSSScanner(
    verbose=True,
    aggressive=True,
    max_threads=100
)

# Run scan
results = scanner.scan_url("https://example.com")
```

### Configuration (config.py)
```python
aggressive_threads = 50       # -a flag
ultra_aggressive_threads = 100  # --ultra flag
insane_threads = 200          # --insane flag
```

## Performance Benchmarks

Example timings (approximate):
- **Standard mode**: 50 payloads × 5 params = ~2-3 minutes
- **Aggressive (50)**: Same scan = ~10-20 seconds
- **Ultra (100)**: Same scan = ~5-10 seconds
- **INSANE (200)**: Same scan = ~3-5 seconds

*Actual performance varies based on network, target, and system*

## When to Use Each Mode

### Standard Mode
- Learning/testing the scanner
- Low-resource systems
- Stable, controlled scans
- Single vulnerability verification

### Aggressive Mode (-a)
- Bug bounty hunting
- Pentest engagements
- Time-sensitive scans
- Modern desktop/laptop

### Ultra Mode (--ultra)
- Large attack surface
- Multiple parameters
- Powerful workstations
- Dedicated security systems

### INSANE Mode (--insane)
- Security research labs
- Server-grade hardware
- Maximum coverage needed
- When time is critical

## Support

Having issues? Check:
1. System resources (RAM, CPU)
2. ChromeDriver installation
3. Network connectivity
4. Target site availability

Still stuck? Open an issue with:
- Mode used (aggressive/ultra/insane)
- Thread count
- System specs
- Error messages

---

**Remember**: With great power comes great responsibility. Use aggressive mode wisely! 🔥
