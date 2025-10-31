# PT Automation Orchestrator

Automated penetration testing orchestration tool that performs 14 security checks on target domains and generates comprehensive HTML/JSON reports.

## Features

14 security checks: Headers, DNS, Subdomains, Nuclei, Screenshot, JS Endpoints, Secret Finder, Wayback Machine, Sucuri, Check-Host, Security Headers, SSL/TLS, Technology Detection, Cookies Analysis.

## Quick Start

### Installation

```bash
# External tools
brew install subfinder
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
export PATH=$PATH:$(go env GOPATH)/bin
nuclei -update -ut

# Python dependencies
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

### Usage

```bash
python3 pt_orchestrator.py example.com
```

Outputs: `pt_output/{domain}.html` and `pt_output/{domain}.json`

## Dependencies

**Python Libraries:** jinja2, playwright, undetected-playwright, requests, beautifulsoup4, python-dotenv, dnspython, pyyaml, requests-file, jsbeautifier, lxml

**External Tools:** subfinder, nuclei, playwright (browser), LinkFinder (optional)

## Logs

Logs: `pt_output/logs/pt_scan_YYYYMMDD_HHMMSS.log`

Debug commands:
```bash
grep "ERROR" pt_output/logs/pt_scan_*.log
tail -f pt_output/logs/pt_scan_$(ls -t pt_output/logs/ | head -1)
```

## TODO

- [ ] Add Docker support
- [ ] Implement database for historical results
- [ ] Add PDF export option
- [ ] Add severity scoring and CVSS mapping
- [ ] Multi-domain batch processing
- [ ] Config file for tool paths and arguments
- [ ] Improve error handling and retry mechanisms
- [ ] Add web interface/dashboard
- [ ] Support for custom Nuclei templates
- [ ] Add API endpoints for integration
- [ ] Implement result comparison feature
- [ ] Add notification system (email/Slack)
- [ ] Performance optimization for large scans

## License

For authorized security testing only. Use responsibly and ethically.
