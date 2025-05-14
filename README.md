# Network Security Auditing and Exploration Tool (NSAET)

This project is a Python-based network exploration and security auditing tool designed to analyze key characteristics of web domains. It performs a series of active scans using standard command-line tools and outputs structured JSON data along with detailed, human-readable reports.

## Features

- Integrates command-line utilities (`nmap`, `openssl`, `nslookup`, `telnet`, `curl`) via Python's `subprocess` module to extract security-related information from each target domain.
- Scans include:
  - IPv4 and IPv6 address resolution
  - HTTP server fingerprinting
  - Detection of insecure HTTP access
  - HTTPS redirection behavior
  - HSTS enforcement
  - Supported TLS versions
  - Reverse DNS lookups
- Extracts certificate chain details including root Certificate Authorities for TLS connections.
- Measures round-trip times (RTT) to each server and identifies the geographic location of IP addresses using the MaxMind GeoLite2 database.
- Outputs results in a structured, portable JSON format, and generates a comprehensive report highlighting:
  - Per-domain scan results
  - Sorted RTT benchmarks
  - Frequency of observed web servers and certificate authorities
  - TLS version and security feature adoption rates
  
## Setup

```bash
git clone https://github.com/LianhaoZ/NSAET.git

python3 -m venv venv
source venv/bin/activate  # For bash/zsh
# or
source venv/bin/activate.csh  # For tcsh

pip install -r requirements.txt
```

## Usage

```bash
# Run the domain scanner
python3 scan.py input_domains.txt output.json

# Generate a report from scan results
python3 report.py output.json report.txt
```
