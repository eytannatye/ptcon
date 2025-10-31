# PT Automation Orchestrator

Automated penetration testing orchestration tool that performs 14 security checks on target domains and generates comprehensive HTML/JSON reports.

## 📋 Features (14 Security Checks)

1. **Headers Check** - HTTP headers analysis with CSP, Cookies, and Referrer-Policy parsing
2. **DNS/Network Layer Analysis** - A, AAAA, MX, TXT records (SPF, DMARC, DKIM) with misconfiguration detection
3. **Subdomain Discovery** - Subdomain discovery using subfinder + live subdomain validation
4. **Nuclei Scan** - Passive vulnerability scanning with templates (technologies + misconfiguration)
5. **Screenshot** - Homepage screenshot capture using Playwright with WAF bypass
6. **JavaScript Endpoint Extraction** - Endpoint extraction from JavaScript files (LinkFinder or regex fallback)
7. **Secret Finder** - Secret discovery in JavaScript files (API keys, tokens, passwords)
8. **Wayback Machine** - Historical URL search via CDX API (limited to 5000 URLs)
9. **Sucuri SiteCheck** - Malware/blacklist/security issues check via API
10. **Check-Host.net** - Host availability and network checks with screenshot
11. **Security Headers** - Security headers check via securityheaders.com with screenshot
12. **SSL/TLS Certificate** - SSL/TLS certificate analysis using Python ssl library (Subject, Issuer, SAN, Expiry)
13. **Technology Detection** - CMS, framework, and infrastructure detection (WordPress, Magento, etc.)
14. **Cookies Analysis** - Detailed cookie analysis with automatic cookie banner acceptance

## 📚 Python Libraries

The tool uses the following libraries (listed in `requirements.txt`):

### Core Libraries
- **jinja2** (>=3.1.2) - HTML report generation with templates
- **playwright** (>=1.40.0) - Screenshots and website navigation (headless browser)
- **undetected-playwright** (>=0.3.0) - WAF/Cloudflare challenge bypass
- **requests** (>=2.31.0) - HTTP/HTTPS requests
- **beautifulsoup4** (>=4.12.0) - HTML parsing (title extraction, header parsing)
- **python-dotenv** (>=1.0.0) - Environment variable management (.env)

### Network & Security
- **dnspython** (>=2.4.2) - DNS queries (A, AAAA, MX, TXT records)
- **urllib3** - HTTPS connection management (SSL warnings suppressed)

### Parsing & Utilities
- **pyyaml** (>=6.0) - YAML parsing (SecretFinder support)
- **requests-file** (>=1.5.1) - Local file reading
- **jsbeautifier** (>=1.14.0) - JavaScript code beautification (SecretFinder support)
- **lxml** (>=4.9.0) - Fast HTML parsing (BeautifulSoup support)

### Built-in Python Modules (included with Python)
- **ssl** - SSL/TLS connection and certificate parsing
- **socket** - Network connections
- **json** - JSON processing
- **logging** - Detailed logging system
- **subprocess** - External tool execution
- **concurrent.futures** - Parallel task execution
- **time** - Execution time measurement
- **signal** - Process termination handling
- **datetime** - Timestamps
- **re** - Regular expressions (for JS endpoint extraction)
- **random** - Randomization for WAF bypass
- **http.cookiejar** - Cookie management

## 🛠️ External Tools Required

### Required

#### subfinder
Subdomain discovery
```bash
# macOS (Homebrew)
brew install subfinder

# Or via Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
export PATH=$PATH:$(go env GOPATH)/bin
```

#### nuclei
Vulnerability scanning with templates
```bash
# Install via Go
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin

# Update templates (important!)
nuclei -update -ut

# If permission issues:
sudo chown -R $(whoami) ~/nuclei-templates
```

#### playwright
Headless browsers (installed via pip + playwright install)
```bash
# After installing requirements.txt:
playwright install chromium
```

### Optional (with fallback)

#### LinkFinder
Endpoint extraction from JavaScript files (if not available, tool uses regex fallback)
```bash
pip3 install linkfinder

# Or from git:
git clone https://github.com/GerbenJavado/LinkFinder.git
cd LinkFinder
pip3 install -r requirements.txt
python3 setup.py install
```

**Note:** If LinkFinder is not installed, the tool uses advanced regex patterns for endpoint extraction.

## 🚀 Installation

### 1. Install External Tools

```bash
# macOS (Homebrew)
brew install subfinder

# Go tools (nuclei)
export PATH=$PATH:$(go env GOPATH)/bin
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Update nuclei templates
nuclei -update -ut

# Fix permissions if needed
sudo chown -R $(whoami) ~/nuclei-templates
```

### 2. Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install packages
pip install -r requirements.txt

# Install Playwright browsers
playwright install chromium
```

### 3. Verify Installation

```bash
# Check external tools
which subfinder
subfinder -version
nuclei -version

# Check Python packages
python3 -c "import jinja2, playwright, requests, bs4, dns.resolver; print('✅ All packages installed')"
```

## 📖 Usage

### Basic Usage

```bash
# Activate virtual environment (if using)
source venv/bin/activate

# Run scan on domain
python3 pt_orchestrator.py example.com
```

### Examples

```bash
# Regular domain
python3 pt_orchestrator.py example.com

# With www/http/https - tool automatically normalizes
python3 pt_orchestrator.py https://www.example.com
python3 pt_orchestrator.py http://example.com/path
python3 pt_orchestrator.py www.example.com:8080

# Tool will automatically normalize input to: example.com
```

### What Happens During Scan?

The tool displays a real-time progress bar:
- Progress percentage
- Active tasks
- Elapsed time and estimated remaining time
- Warnings if tasks get stuck

## 📂 Output Structure

All outputs are saved in `pt_output/`:

```
pt_output/
├── {domain}.json              # Complete JSON report with all data
├── {domain}.html              # Comprehensive HTML report with visual results
├── screenshots/               # Screenshots
│   ├── {domain}.png           # Main screenshot
│   ├── {domain}_checkhost.png
│   ├── {domain}_securityheaders.png
│   └── {domain}_cookies.png
└── logs/                      # Detailed logs
    └── pt_scan_YYYYMMDD_HHMMSS.log
```

### HTML Report Features

The HTML report includes:
- **Technology Detection** - Cards with detected technologies
- **DNS/Network Analysis** - Detailed tables of DNS records
- **Subdomains Grid** - Visual display of live subdomains with titles
- **Security Vulnerabilities** - Nuclei findings with raw output
- **Screenshots** - Thumbnails that open in lightbox (click to enlarge)
- **Cookies Analysis** - Detailed table of all cookies
- **JavaScript Endpoints** - List with real-time search
- **Wayback URLs** - List with real-time search
- **SecretFinder Results** - Secrets found
- **All Checks** - Comprehensive table of all results

## 🔍 Debugging with Logs

### Log Location

Logs are saved in: `pt_output/logs/pt_scan_YYYYMMDD_HHMMSS.log`

Each scan creates a new log file with timestamp (format: `pt_scan_20251101_002321.log`).

### Log Types

The system uses Python `logging` with the following levels:

- **INFO** - General information about task execution (start, completion, status)
- **WARNING** - Warnings (approaching timeouts, minor issues, retries)
- **ERROR** - Errors (failed commands, timeouts, exceptions)
- **DEBUG** - Technical details (full commands, debugging info)

**Log Format:**
```
YYYY-MM-DD HH:MM:SS [LEVEL] [TASK_NAME] Message
```

### How to Debug Errors

#### 1. Find Latest Log File

```bash
# List files by date (newest first)
ls -lt pt_output/logs/ | head -1

# Or open the latest directly
cat pt_output/logs/$(ls -t pt_output/logs/ | head -1)
```

#### 2. Search for Specific Errors

```bash
# Errors only
grep "ERROR" pt_output/logs/pt_scan_*.log

# Errors for specific task (e.g., NUCLEI)
grep "\[NUCLEI\].*ERROR" pt_output/logs/pt_scan_*.log

# Timeouts
grep "TIMEOUT" pt_output/logs/pt_scan_*.log

# SSL errors
grep "\[SSL\].*ERROR" pt_output/logs/pt_scan_*.log

# WAF bypass errors
grep "\[WAF\]" pt_output/logs/pt_scan_*.log
```

#### 3. Check Specific Tasks

```bash
# All information about a task (e.g., HEADERS)
grep "\[HEADERS\]" pt_output/logs/pt_scan_*.log

# Execution duration of all tasks
grep "completed in" pt_output/logs/pt_scan_*.log

# Failed commands
grep "Command failed" pt_output/logs/pt_scan_*.log

# Successful tasks
grep "✓" pt_output/logs/pt_scan_*.log
```

#### 4. Real-time Monitoring

```bash
# Tail log in real-time (auto-updates during scan)
tail -f pt_output/logs/pt_scan_$(ls -t pt_output/logs/ | head -1)

# With filtering for errors and warnings only
tail -f pt_output/logs/pt_scan_*.log | grep --line-buffered "ERROR\|WARNING"

# Only info about specific task (e.g., NUCLEI)
tail -f pt_output/logs/pt_scan_*.log | grep --line-buffered "\[NUCLEI\]"
```

#### 5. Log Examples

**Successful log:**
```
2025-11-01 00:23:21,229 [INFO] [HEADERS] Starting headers check for example.com
2025-11-01 00:23:21,229 [INFO] [HEADERS] Trying HTTPS connection (max 30 redirects)...
2025-11-01 00:23:22,725 [INFO] [HEADERS] ✓ HTTPS succeeded in 1.5s (Status: 200, 0 redirects)
2025-11-01 00:23:22,726 [INFO] [HEADERS] Completed in 1.5s
```

**Log with timeout:**
```
2025-11-01 00:23:21,235 [INFO] [NUCLEI] Starting command: nuclei -u https://example.com...
2025-11-01 00:23:21,236 [INFO] [NUCLEI] Timeout set to: 300s
2025-11-01 00:28:21,502 [ERROR] [NUCLEI] ⚠️ TIMEOUT after 300s (actual time: 300.1s)
2025-11-01 00:28:21,503 [ERROR] [NUCLEI] Command that timed out: nuclei -u https://example.com...
```

**Log with error:**
```
2025-11-01 00:23:21,502 [INFO] [CHECKHOST] Querying check-host.net API for www.example.com...
2025-11-01 00:23:21,949 [ERROR] [CHECKHOST] Command failed with return code 1
2025-11-01 00:23:21,950 [ERROR] [CHECKHOST] STDERR: Connection timeout
```

**Successful log with details:**
```
2025-11-01 00:23:21,235 [INFO] [NUCLEI] Starting command: nuclei -u https://example.com...
2025-11-01 00:23:21,236 [INFO] [NUCLEI] Timeout set to: 300s
2025-11-01 00:24:40,473 [INFO] [NUCLEI] Command completed successfully in 79.2s
2025-11-01 00:24:40,475 [INFO] [NUCLEI] Found 17 findings
```

#### 6. Common Errors and Solutions

##### "command not found" - Tool Not Found

**Symptoms:**
```
[ERROR] [SUBDOMAINS] Command failed with return code 127
[ERROR] [SUBDOMAINS] STDERR: /bin/sh: subfinder: command not found
```

**Solution:**
```bash
# Check if tool is installed
which subfinder
which nuclei

# Check PATH
echo $PATH | grep -o "$(go env GOPATH)/bin"

# If missing, add to PATH
export PATH=$PATH:$(go env GOPATH)/bin
# Add to ~/.zshrc or ~/.bashrc for persistence
```

##### "TEMPLATE LOADING" errors (Nuclei)

**Symptoms:**
```
[ERROR] [NUCLEI] STDERR: [WRN] templates: warning: error loading template...
```

**Solution:**
```bash
# Update templates
nuclei -update -ut

# Fix permissions
sudo chown -R $(whoami) ~/nuclei-templates

# Verify templates exist
ls -la ~/nuclei-templates/
```

##### "Failed to get certificate" (SSL)

**Symptoms:**
```
[WARNING] [SSL] Failed to get certificate: [Errno 111] Connection refused
```

**Solution:**
- Check domain is open on port 443: `curl -I https://example.com`
- Check for firewall/blocking
- Check logs for specific error message

##### "Timeout" warnings

**Symptoms:**
```
[WARNING] [NUCLEI] Command took 285.0s (close to timeout of 300s)
```

**Solution:**
- Long tasks can take time (nuclei up to 5 minutes is normal)
- If task made no progress at all - system will automatically terminate it
- Check logs to see if task is progressing or stuck

##### "Cloudflare challenge" / "Human verification"

**Symptoms:**
```
[WARNING] [SCREENSHOT] Cloudflare challenge detected, waiting...
```

**Solution:**
- System tries to bypass automatically with `undetected-playwright`
- If still failing - check logs for `[WAF]` messages
- Sometimes need to wait a few seconds

##### "Lightbox not opening" (HTML report)

**Symptoms:**
- Images don't open when clicking

**Solution:**
- Fixed in latest commit
- If still issue, check browser console (F12) for JavaScript errors
- Ensure `openLightbox` is defined in global scope

#### 7. Performance Analysis

```bash
# Summarize execution times of all tasks
grep "completed in" pt_output/logs/pt_scan_*.log | awk '{print $NF}' | sort -n

# Find longest task
grep "completed in" pt_output/logs/pt_scan_*.log | sort -t's' -k2 -rn | head -1

# Count successful vs failed tasks
echo "Success: $(grep '✓' pt_output/logs/pt_scan_*.log | wc -l)"
echo "Errors: $(grep 'ERROR' pt_output/logs/pt_scan_*.log | wc -l)"
```

### Viewing HTML Report

```bash
# macOS
open pt_output/example.com.html

# Linux
xdg-open pt_output/example.com.html

# Windows
start pt_output/example.com.html

# Or specific browser
google-chrome pt_output/example.com.html
```

## ⚙️ Configuration

### Timeouts

Defaults in `pt_orchestrator.py`:

```python
TIMEOUTS = {
    "headers": 30,           # 30 seconds
    "subdomains": 120,       # 2 minutes
    "nuclei": 300,           # 5 minutes
    "screenshot": 60,        # 1 minute
    "dns": 30,               # 30 seconds
    "js_endpoints": 120,     # 2 minutes
    "secretfinder": 300,     # 5 minutes
    "cookies": 180,          # 3 minutes
}
```

You can modify these values in `pt_orchestrator.py` as needed.

### Parallel Execution

The system runs up to **8 tasks in parallel** (ThreadPoolExecutor).

You can modify in `pt_orchestrator.py`:
```python
with ThreadPoolExecutor(max_workers=8) as executor:
```

### Domain Normalization

The tool automatically normalizes domain input:
- Adds `https://` if missing
- Removes `www.` if present (except for specific checks like Check-Host)
- Removes paths (`/path/to/page`) and ports (`:8080`)
- Normalizes domain to correct format

### Stuck Process Detection

The system detects stuck tasks (not progressing) and automatically terminates them:
- Checks for progress every 10 seconds
- If no progress for extended time - terminates the process
- Logs that it terminated the process

## 🔒 Security and Behavior

- **Timeouts**: All scans respect timeouts to prevent hanging
- **Rate Limiting**: API calls include 1-2 second delays
- **WAF Bypass**: Cloudflare/WAF bypass using `undetected-playwright` + fingerprinting
- **Audit Trail**: Logs include who ran, when, and what (timestamped logs)
- **Raw Outputs**: All raw outputs are preserved as evidence
- **Process Cleanup**: Failed processes are terminated cleanly (process tree killing)

**⚠️ Ethical Use:** Only use on domains you own or have explicit permission to test!

## 🐛 Troubleshooting

### Installation Issues

**Python packages not installing:**
```bash
# Update pip
pip install --upgrade pip

# Try again
pip install -r requirements.txt
```

**Playwright browsers not installing:**
```bash
playwright install chromium --force
```

**Go tools not found:**
```bash
# Verify Go is installed
go version

# Add Go bin to PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.zshrc
```

### Runtime Issues

**"ModuleNotFoundError":**
```bash
# Ensure venv is active
source venv/bin/activate

# Reinstall
pip install -r requirements.txt
```

**"Permission denied" in logs:**
```bash
# Check permissions
ls -la pt_output/logs/

# Fix permissions
chmod -R 755 pt_output/
```

**Scan gets stuck:**
- Check logs for warnings
- Check for stuck processes: `ps aux | grep nuclei`
- Kill stuck processes: `pkill -f nuclei`

## 📝 Project Structure

```
pt_automation/
├── pt_orchestrator.py      # Main code
├── requirements.txt         # Python dependencies
├── templates/
│   └── report.html          # HTML report template
├── tools/
│   └── secretfinder/       # SecretFinder tool
├── pt_output/              # Outputs (not in git)
│   ├── {domain}.json
│   ├── {domain}.html
│   ├── screenshots/
│   └── logs/
└── README.md               # This file
```

## 🔄 Recent Updates

- ✅ Fixed lightbox - images now open properly
- ✅ Improved SSL certificate parsing
- ✅ Enhanced JS endpoints extraction with advanced regex
- ✅ Cookies analysis with automatic banner acceptance
- ✅ Improved WAF bypass with undetected-playwright
- ✅ Stuck process detection
- ✅ Active progress bar with estimated time

## 📝 License

This tool is intended for authorized security testing only. Use responsibly and ethically.

## 🤝 Contributions

Open to suggestions, bug fixes, and additional features.

---

**Note:** The HTML report includes lightbox for images, real-time search, detailed displays, and all information is organized in an easy-to-read format.
