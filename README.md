# 🔎 OrionToolkit

> *"Because curiosity is the beginning of mastery."*

**OrionToolkit** is a comprehensive Python-based OSINT, reconnaissance, and security assessment toolkit designed for cybersecurity professionals, ethical hackers, and curious minds. It runs on **Termux (Android)**, **Linux**, **Windows**, and **macOS**.

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Termux Compatible](https://img.shields.io/badge/Termux-Compatible-brightgreen.svg)](https://termux.com)

---

## ✨ Features

### 15 Ready-to-Use Modules

| # | Module | Category | Description |
|---|--------|----------|-------------|
| 1 | **Domain Information** | 🌐 OSINT | Resolve hostname, aliases, IP addresses |
| 2 | **DNS Lookup** | 🌐 OSINT | Query A, AAAA, MX, NS, TXT, SOA, CNAME, and more |
| 3 | **IP Information** | 🌐 OSINT | IP validation, version, public/private detection |
| 4 | **My Private IP** | 🌐 OSINT | Show your local network IP address |
| 5 | **HTTP Headers** | 🔍 Recon | Inspect response headers with security scoring |
| 6 | **File Hash** | 🔐 Hash | Generate MD5, SHA-1, SHA-256, SHA-512, BLAKE2b |
| 7 | **Login Brute-Force** | 💥 Exploit | Form-based auth cracking with CSRF handling |
| 8 | **Subdomain Enumeration** | 🔍 Recon | Passive (crt.sh) + active (DNS brute-force) |
| 9 | **Port Scanner** | 🔍 Recon | Multithreaded TCP port scanning |
| 10 | **Directory Fuzzer** | 🔍 Recon | Web path discovery with extension brute-force |
| 11 | **Whois Lookup** | 🌐 OSINT | Domain registration and ownership info |
| 12 | **GeoIP Lookup** | 🌐 OSINT | IP geolocation via ip-api.com (no API key) |
| 13 | **SSL Checker** | 🔍 Recon | Certificate details, expiry, SANs, TLS version |
| 14 | **Phone Lookup** | 🌐 OSINT | Phone number validation and country identification |
| 15 | **Password Generator** | 🔐 Hash | Cryptographically secure random passwords |

---

## 📁 Project Structure

```text
OrionToolkit/
├── main.py              # Main entry point
├── requirements.txt     # Python dependencies
├── README.md            # This file
├── LICENSE              # MIT License
├── .gitignore
└── modules/
    ├── __init__.py      # Package marker
    ├── domain.py        # Domain analysis
    ├── dns_lookup.py    # DNS record enumeration
    ├── ip_lookup.py     # IP address lookup
    ├── headers.py       # HTTP header analysis
    ├── hashing.py       # File hash generation
    ├── bruteforce.py    # Login brute-force engine
    ├── subdomain.py     # Subdomain enumeration
    ├── port_scanner.py  # TCP port scanner
    ├── dir_fuzzer.py    # Directory fuzzer
    ├── whois_lookup.py  # Whois domain lookup
    ├── geoip.py         # GeoIP geolocation
    ├── ssl_checker.py   # SSL certificate checker
    ├── phone_lookup.py  # Phone number lookup
    └── password_gen.py  # Password generator
---

## 🚀 Installation

### PC (Linux / Windows / macOS)

```bash
# Clone the repository
git clone https://github.com/kiddanger-tech/OrionToolkit.git
cd OrionToolkit

# Install dependencies
pip install -r requirements.txt

# Run the toolkit
python main.py
# Install Termux from F-Droid or Google Play
# Then run:
pkg update && pkg upgrade -y
pkg install python git -y

# Clone the repository
git clone https://github.com/kiddanger-tech/OrionToolkit.git
cd OrionToolkit

# Install dependencies
pip install -r requirements.txt

# Run the toolkit
python main.py
termux-setup-storage

