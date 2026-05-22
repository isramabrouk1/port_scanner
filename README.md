# 🔐 Port Scanner with CVE Correlation Engine

> A professional-grade Python security audit tool that performs concurrent TCP port scanning, service detection, vulnerability correlation via NVD API, and automated HTML report generation.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Status](https://img.shields.io/badge/Status-Production--Ready-brightgreen)

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Project Structure](#-project-structure)
- [Technical Deep Dive](#-technical-deep-dive)
- [Security & Ethics](#-security--ethics)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🎯 Overview

This tool automates the reconnaissance phase of a cybersecurity audit by:

1. **Scanning** target hosts for open TCP ports using concurrent connection attempts
2. **Identifying** services via banner grabbing and port-to-service mapping
3. **Correlating** detected services with known vulnerabilities from a curated local CVE database + NVD API fallback
4. **Scoring** risk using CVSS v3.1 thresholds (Critical/High/Medium/Low)
5. **Generating** professional HTML audit reports with visualizations

**Built for**: Security engineers, SOC analysts, penetration testers, and DevSecOps teams who need rapid vulnerability triage without relying on black-box tools.

---

## ✨ Features

### 🔍 Scanning Engine
- **Concurrent TCP Connect Scan**: ThreadPoolExecutor-based parallel scanning (100 ports in ~2 seconds vs 147s sequential)
- **Smart Timeout Handling**: Distinguishes `closed` (RST received) vs `filtered` (SYN dropped) ports at the socket level
- **Banner Grabbing**: Service fingerprinting via protocol-specific probes (SSH, HTTP, FTP, etc.)
- **Configurable CLI**: `--host`, `--ports`, `--threads`, `--timeout`, `--verbose`, `--report`

### 🛡️ Vulnerability Correlation
- **Local SQLite Database**: 50+ curated real-world CVEs across common services (OpenSSH, Apache, vsftpd, MySQL, etc.)
- **NVD API Fallback**: Automatic query to NIST National Vulnerability Database when local DB has no matches
- **Intelligent Caching**: File-based JSON cache prevents redundant API calls and handles rate limits gracefully
- **CVSS v3.1 Scoring**: Official severity thresholds applied consistently:
  ```
  Critical: 9.0–10.0 | High: 7.0–8.9 | Medium: 4.0–6.9 | Low: 0.1–3.9
  ```

### 📊 Reporting
- **Professional HTML Reports**: Jinja2 templating with Chart.js visualizations
- **Five Required Sections**: Target info, scan summary, port/service table, vulnerability details, risk assessment + recommendations
- **Actionable Remediation**: Per-service security guidance based on detected risks

### 🔧 Engineering Quality
- **Modular Architecture**: Separation of concerns across 6 focused Python modules
- **Error Resilience**: Graceful handling of DNS failures, API timeouts, network errors
- **No External Dependencies Beyond Standard Lib**: Except `requests`, `python-dotenv`, `jinja2` for API/reporting

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────┐
│                   scanner.py                     │
│  • CLI entry point (argparse)                    │
│  • TCP scanning + banner grabbing (socket)       │
│  • Threading orchestration (ThreadPoolExecutor)  │
│  • Calls correlator → reporter pipeline          │
└────────────┬────────────────────────────────────┘
             │
             ▼
┌─────────────────────────────────────────────────┐
│                correlator.py                     │
│  • Maps port → service keyword (COMMON_SERVICES) │
│  • Queries local DB first, then NVD API          │
│  • Calculates risk level from highest CVSS score │
│  • Attaches per-service recommendations          │
└────────────┬────────────────────────────────────┘
             │
     ┌───────┴───────┐
     ▼               ▼
┌─────────┐   ┌─────────────┐
│cve_db.py│   │  nvd_api.py │
│• SQLite │   │• REST API  │
│• 50 CVEs│   │• Caching   │
│• Query  │   │• Rate limit│
└─────────┘   └─────────────┘
             │
             ▼
┌─────────────────────────────────────────────────┐
│                 reporter.py                      │
│  • Jinja2 HTML templating                        │
│  • Chart.js risk distribution visualization      │
│  • Outputs professional audit report             │
└─────────────────────────────────────────────────┘
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Setup
```bash
# Clone the repository
git clone https://github.com/yourusername/port-scanner-cve.git
cd port-scanner-cve

# Install dependencies
pip install -r requirements.txt

# Configure environment variables (optional but recommended)
cp .env.example .env
# Edit .env and add your NVD API key:
# NVD_API_KEY=your_key_here
# Get a free key at: https://nvd.nist.gov/developers/request-an-api-key

# Initialize the CVE database (runs automatically on first scan, but can be pre-seeded)
python cve_db.py
```

### Requirements (`requirements.txt`)
```txt
requests>=2.28.0
python-dotenv>=0.19.0
jinja2>=3.1.0
```

---

## 🚀 Quick Start

### Basic Scan
```bash
python scanner.py --host scanme.nmap.org --start-port 1 --end-port 100
```

### Full Audit with Report
```bash
python scanner.py \
  --host target.example.com \
  --start-port 1 \
  --end-port 1000 \
  --threads 50 \
  --timeout 2.0 \
  --report audit_report.html
```

### Verbose Mode (show all port states)
```bash
python scanner.py --host scanme.nmap.org --ports 20-85 --verbose
```

---

## 📖 Usage Examples

### Example 1: Scan a single host, default ports
```bash
$ python scanner.py --host scanme.nmap.org

[INFO] Target   : scanme.nmap.org (45.33.32.156)
[INFO] Ports    : 1 - 100
[INFO] Threads  : 100
[INFO] Started  : 2026-05-15 22:21:23

PORT     SERVICE      STATUS       BANNER
------------------------------------------------------------
22      SSH         open        SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.
Risk     : Critical (CVSS 9.8)
CVEs     : 6 found
  CVE-2023-38408     9.8    Remote code execution via ssh-agent...
  CVE-2020-15778     7.8    Command injection in scp recursive...
Recommend: Disable root login, enforce key-based auth...

80      HTTP        open        HTTP/1.1 200 OK...
Risk     : Critical (CVSS 9.8)
CVEs     : 7 found
...

[SUMMARY] Scanned  : 100 ports
[SUMMARY] Open     : 2
[SUMMARY] Filtered : 98
```

### Example 2: Generate HTML report
```bash
$ python scanner.py --host scanme.nmap.org --report report.html
[REPORT] Report saved to: report.html
```
→ Open `report.html` in any browser for a professional audit document with:
- Executive summary dashboard
- Risk distribution pie chart (Chart.js)
- Detailed vulnerability tables with CVE IDs, scores, descriptions
- Color-coded severity badges
- Actionable remediation recommendations

### Example 3: Tune for slow networks
```bash
python scanner.py --host target.com --threads 10 --timeout 5.0
```
→ Reduces thread count and increases timeout to avoid triggering rate limiting or IDS alerts.

---

## 📁 Project Structure

```
port-scanner-cve/
├── scanner.py          # Main CLI: scanning, threading, orchestration
├── cve_db.py           # SQLite database: init, seed, query functions
├── nvd_api.py          # NVD REST API: fetch, parse, cache, rate-limit handling
├── correlator.py       # Core logic: service→keyword mapping, risk scoring, recommendations
├── reporter.py         # HTML report generation via Jinja2 + Chart.js
├── templates/
│   └── report_template.html  # Jinja2 template for audit reports
├── data/
│   ├── vulns.db        # SQLite database (auto-created)
│   └── cache/          # JSON cache for NVD API responses
├── .env                # Environment variables (NVD_API_KEY)
├── .env.example        # Template for .env
├── requirements.txt    # Python dependencies
├── README.md           # This file
└── LICENSE             # MIT License
```

---

## 🔬 Technical Deep Dive

### How Port States Are Determined
| State | Network Behavior | Python Exception | Meaning |
|-------|-----------------|------------------|---------|
| `open` | SYN → SYN+ACK received | None | Service is listening |
| `closed` | SYN → RST+ACK received | `ConnectionRefusedError` | Port reachable, nothing listening |
| `filtered` | SYN → dropped silently | `socket.timeout` | Firewall/IDS intercepting |

### CVE Correlation Logic
```python
# 1. Port 22 detected → COMMON_SERVICES[22] = "SSH"
# 2. "SSH" → SERVICE_TO_KEYWORD["SSH"] = "openssh"
# 3. Query local DB: SELECT * FROM cves WHERE service = 'openssh'
# 4. If empty → fetch_cves_from_api("openssh")
# 5. Take highest CVSS score → map to severity via official thresholds
# 6. Attach recommendation from RECOMMENDATIONS dict
```

### Why Local DB + API Fallback?
| Approach | Pros | Cons |
|----------|------|------|
| **Local DB only** | Fast, offline, deterministic | Limited coverage (50 CVEs) |
| **API only** | Full NVD coverage (250k+ CVEs) | Slow, rate-limited, network-dependent |
| **Hybrid (this tool)** | ✅ Fast for common services ✅ Fallback for edge cases ✅ Cache reduces API calls | Slightly more complex logic |

### CVSS Scoring Implementation
We use the **base score** from NVD (authoritative) and apply **official severity thresholds**:
```python
def _get_risk_level(score):
    if score >= 9.0: return "Critical"
    elif score >= 7.0: return "High"
    elif score >= 4.0: return "Medium"
    elif score > 0.0: return "Low"
    else: return "Informational"
```
*Note: Environmental/temporal metrics require target context not available in black-box scans—documented limitation.*

---

## ⚠️ Security & Ethics

### Authorized Use Only
This tool is designed for:
- ✅ Security audits of systems you own or have explicit written permission to test
- ✅ Educational purposes in controlled lab environments
- ✅ Internal vulnerability assessment within organizational policy

### Not For:
- ❌ Unauthorized scanning of third-party systems
- ❌ Malicious reconnaissance or attack preparation
- ❌ Any activity violating local computer crime laws

### Operational Considerations
- **Rate Limiting**: High thread counts may trigger IDS/IPS alerts. Use `--threads 10-20` for stealthier scans.
- **API Keys**: Never commit `.env` to version control. Use environment variables in production.
- **Data Sensitivity**: Reports may contain vulnerability details—store and share securely.

---

## 🛠️ Troubleshooting

| Issue | Solution |
|-------|----------|
| `Cannot resolve hostname` | Verify DNS or use IP address directly |
| `All ports filtered` | Target may be behind aggressive firewall; reduce `--threads`, increase `--timeout` |
| `NVD API timeout` | Check internet connection; increase timeout in `nvd_api.py`; verify API key |
| `Database not found` | Run `python cve_db.py` to initialize, or ensure `data/vulns.db` exists |
| `Report not generating` | Verify `templates/report_template.html` exists; check Jinja2 installation |

---

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

**Before submitting**: Ensure all tests pass, update documentation, and follow PEP 8 style guidelines.

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

## 🙏 Acknowledgments

- [NIST National Vulnerability Database](https://nvd.nist.gov) for CVE data and API
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) for web security training
- [Scanme.Nmap.Org](https://scanme.nmap.org) for legal testing target
- The open-source Python community for `socket`, `concurrent.futures`, `sqlite3`, and `jinja2`

---

> **Built by isra Mabrouk** | Cybersecurity Engineering Student  
> 📧 isramabrouk56@gmail.com | 🔗 [LinkedIn](linkedin.com/in/isra-mabrouk-682916387) | 🐙 [GitHub](https://github.com/isramabrouk1)

*This project was developed as part of an academic cybersecurity curriculum. All vulnerability data is sourced from public, authoritative databases.*
