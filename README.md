# 🚀 XssDoom - Advanced XSS Scanner

![XSS Scanner](https://img.shields.io/badge/XSS-Scanner-red)
![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Selenium](https://img.shields.io/badge/Selenium-4.15%2B-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

A comprehensive, feature-rich Cross-Site Scripting (XSS) vulnerability scanner with both CLI and GUI interfaces. Designed for security professionals, penetration testers, and bug bounty hunters.

##  Features

### 🔥 **NEW: Aggressive Parallel Scanning**
- **Multi-threaded Scanning**: Run with 50, 100, or 200+ parallel browser instances
- **Lightning Fast**: Scan at speeds like having 1000 people testing simultaneously
- **Scalable Performance**: Choose from Aggressive, Ultra, or INSANE mode based on your system
- **Smart Resource Management**: Automatic browser pooling and thread-safe operations

###  **Advanced Detection**
- **Multiple Detection Methods**: Alert-based, reflection analysis, DOM-based, and attribute context detection
- **Comprehensive Testing**: URL parameters, fragments, form inputs, and headers
- **Smart Payloads**: Categorized payloads (basic, advanced, polyglot) for targeted testing
- **Context-Aware Analysis**: Understands where payloads are reflected and their exploitability

###  **User Interfaces**
- **CLI Interface**: Fast, scriptable command-line interface for automated testing
- **GUI Interface**: Modern, intuitive graphical interface with real-time monitoring
- **Real-time Results**: Live progress updates and immediate vulnerability reporting

###  **Professional Reporting**
- **Multiple Formats**: Console, JSON, and detailed text reports
- **Vulnerability Classification**: Categorized by type, severity, and detection method
- **Export Capabilities**: Save and load scan results for later analysis

###  **Technical Features**
- **Chrome Automation**: Uses Selenium WebDriver for accurate JavaScript execution
- **Parallel Processing**: Efficient scanning with configurable workers
- **Error Resilience**: Robust error handling and recovery mechanisms
- **Customizable Settings**: Adjustable timeouts, delays, and scan options

##  Quick Start

### Prerequisites

- **Python 3.8+**
- **Google Chrome** browser
- **ChromeDriver** (matching your Chrome version)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/yourusername/xxsDoom.git
   cd xxsDoom
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Setup ChromeDriver**
   - Download from: https://chromedriver.chromium.org/
   - Ensure it matches your Chrome version
   - Place in system PATH or project directory

### Verify Installation

```bash
# 1. Check if everything is installed correctly
python check_setup.py

# 2. Run automated tests
python test_scanner.py

# 3. Test with a known vulnerable site (safe to test)
python xsscan.py "http://testphp.vulnweb.com/search.php?test=query" -v
```

##  Usage

### 🔥 Aggressive Parallel Scanning (NEW!)

**Scan like 1000 people working simultaneously:**

```bash
# Aggressive mode - 50 parallel threads (50x faster)
python xsscan.py -a https://example.com

# Ultra aggressive - 100 parallel threads (100x faster)
python xsscan.py --ultra https://example.com

# INSANE mode - 200+ parallel threads (Maximum speed!)
python xsscan.py --insane https://example.com

# Custom thread count
python xsscan.py --threads 75 https://example.com
```

**Mode Comparison:**
| Mode | Speed | Resource Usage | Best For |
|------|-------|----------------|----------|
| Standard | 1x | Low | Safe, stable scans |
| Aggressive (`-a`) | ~50x | Medium | Fast scanning |
| Ultra (`--ultra`) | ~100x | High | Powerful systems |
| INSANE (`--insane`) | ~200x | Very High | Maximum speed |

📖 **[Full Aggressive Mode Guide](AGGRESSIVE_MODE.md)**

### Command Line Interface (CLI)

```bash
# Basic scan
python xsscan.py https://example.com

# Advanced scan with all payloads
python xsscan.py https://example.com -c all -v

# Skip form testing
python xsscan.py https://example.com --no-forms

# Custom timeout and output
python xsscan.py https://example.com --timeout 30 -o scan_report.json
```

#### CLI Options
```
Usage: xsscan.py [OPTIONS] URL

Options:
  -c, --category [basic|advanced|polyglot|all]  Payload category
  -o, --output FILE                             Output file for results
  --no-forms                                    Skip form testing
  --no-headers                                  Skip header testing
  --timeout SECONDS                             Request timeout (default: 15)
  --delay SECONDS                               Delay between requests (default: 0.5)
  -v, --verbose                                 Verbose output
  
  🔥 Aggressive Parallel Mode:
  -a, --aggressive                              Enable aggressive mode (50 threads)
  --ultra                                       Ultra aggressive mode (100 threads)
  --insane                                      INSANE mode (200+ threads)
  --threads N                                   Custom thread count
  
  -h, --help                                    Show help message
```

### Graphical Interface (GUI)

```bash
# Launch the GUI
python gui.py
```

#### GUI Features
- **Pre-configured Test URLs**: Quick testing with known vulnerable sites
- **Real-time Console**: Live output during scanning
- **Results Dashboard**: Organized vulnerability display
- **Export Functionality**: Save reports in multiple formats
- **Configurable Settings**: Adjust scan parameters easily

##  Project Structure

```
xsscan/
├── payloads/                 # Organized payload directory
│   ├── basic.txt            # Common XSS payloads
│   ├── advanced.txt         # Advanced evasion payloads
│   └── polyglot.txt         # Polyglot payloads
├── results/                 # Scan results directory
│   ├── scans/               # Auto-saved scan results
│   └── reports/             # Generated reports
├── xsscan.py               # Main CLI scanner
├── gui.py                  # Graphical user interface
├── scanner.py              # Core scanning engine
├── reporter.py             # Report generation
├── config.py               # Configuration management
└── requirements.txt        # Project dependencies
```

## 🔧 Configuration

### Payload Categories

- **basic**: Common XSS payloads for quick testing
- **advanced**: Sophisticated payloads with evasion techniques
- **polyglot**: Multi-context payloads that work in various scenarios
- **all**: Combine all payload categories

### Scanner Settings

Modify `config.py` to adjust:
- Request timeouts and delays
- Browser user agent and headless mode
- Detection strings and patterns
- Parallel worker count

##  Sample Output

### CLI Output
```
╔══════════════════════════════════════════════════╗
║                 XSScan Scan Results              ║
╚══════════════════════════════════════════════════╝

 SCAN DETAILS:
────────────────
• Scan ID: 1705589321
• Target: https://vulnerable-site.com/search
• Scan Time: 23.45 seconds
• Vulnerabilities Found: 3

 VULNERABILITIES FOUND:
──────────────────────────

 VULNERABILITY #1:
   • Type: URL Parameter
   • Parameter: 'q'
   • Payload: <script>alert('XSS')</script>
   • Detection Method: alert_execution
   • URL: https://vulnerable-site.com/search?q=<script>alert('XSS')</script>

 VULNERABILITY #2:
   • Type: Form Input
   • Input: 'username'
   • Payload: "><svg onload=alert(1)>
   • Detection Method: dangerous_reflection
   • URL: https://vulnerable-site.com/login
```

### GUI Interface
The GUI provides:
- **Real-time console** with color-coded messages
- **Vulnerabilities table** with sortable columns
- **Scan summary** with statistics and breakdowns
- **Progress indicators** and time tracking

##  Development

### Adding New Payloads

1. **Add to payload files** in `payloads/` directory:
   ```bash
   echo 'your-new-payload' >> payloads/advanced.txt
   ```

2. **Payloads are automatically loaded** and deduplicated

### Extending Detection Methods

Modify `scanner.py` to add new detection techniques:

```python
def new_detection_method(self, url, payload):
    # Implement your detection logic
    if vulnerability_found:
        return {
            'vulnerable': True,
            'method': 'new_method',
            'evidence': 'Detection evidence'
        }
    return {'vulnerable': False}
```

### Custom Reports

Extend `reporter.py` to support additional output formats:

```python
def generate_html_report(self, results, scan_time):
    # Implement HTML report generation
    pass
```

##  Troubleshooting

### Common Issues

1. **ChromeDriver not found**
   ```
   Solution: Download ChromeDriver and add to PATH
   ```

2. **Browser initialization fails**
   ```
   Solution: Check Chrome version matches ChromeDriver
   ```

3. **No vulnerabilities found on test sites**
   ```
   Solution: Verify test site is accessible and vulnerable
   ```

4. **GUI fails to start**
   ```
   Solution: Run simple_gui.py first to test tkinter
   ```

### Debug Mode

Enable verbose output for detailed debugging:

```bash
python xsscan.py https://example.com -v
```

##  Performance Tips

- **Use appropriate timeouts** based on target responsiveness
- **Limit form testing** on sites with many forms using `--no-forms`
- **Start with basic payloads** then escalate to advanced
- **Use headless mode** for faster scanning (enabled by default)

##  Contributing

We welcome contributions! 

### Areas for Contribution
- New detection methods
- Additional payload categories
- Enhanced reporting formats
- Performance optimizations
- GUI improvements


##  Legal Disclaimer

This tool is designed for:
- Security research and education
- Authorized penetration testing
- Bug bounty hunting with proper permissions

**Always ensure you have explicit permission** before scanning any website. The authors are not responsible for misuse of this tool.



##  Acknowledgments

- Selenium WebDriver team
- Security researchers who contributed payloads
- Open-source security community

---

**Happy Scanning!** 
