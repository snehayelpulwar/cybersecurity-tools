# Cybersecurity Tools

Small, practical security tools built while learning offensive security concepts. Each tool is self-contained in its own folder.

## ⚠️ Legal Notice

These tools are for educational use and authorized testing only. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate computer misuse laws.

## Tools

### Port Scanner
A multithreaded TCP port scanner that checks a target for open ports.

**Usage:**
cd port_scanner
python port_scanner.py <target> -p <port-range>


**Examples:**

python port_scanner.py 127.0.0.1 -p 1-1024
python port_scanner.py scanme.nmap.org -p 20-100


**Features:**
- Multithreaded scanning (200 concurrent workers by default) — scans 1024 ports in ~3 seconds instead of ~9 minutes with sequential scanning
- Identifies common services (SSH, HTTP, SMB, RDP, etc.)
- Supports port ranges (`1-1024`) or specific ports (`80,443,8080`)
- Configurable timeout and worker count

**Sample output:**

[OPEN] Port 22 (SSH)
[OPEN] Port 80 (HTTP)

Scan complete in 3.10 seconds
Open ports found: 2
Ports: 22, 80

### Log Analyzer
Scans log files for signs of attack: brute-force login attempts, high-volume requests from one IP, and common attack signatures (SQL injection, XSS, directory traversal, WordPress scanning).

**Usage:**
cd log_analyzer
python log_analyzer.py <logfile>


**Example:**

python log_analyzer.py sample.log


**Features:**
- Flags IPs with repeated failed logins (configurable threshold, default 5+)
- Flags IPs with unusually high request volume (default 100+)
- Detects common attack patterns: SQL injection, XSS, directory traversal, WordPress scanning
- Works with Apache/Nginx-style access logs and Linux auth logs

**Sample output:**

[Repeated failed logins] (threshold: 5+)
⚠ 10.0.0.5 — 6 failed attempts (possible brute force)

[Suspicious request patterns]
⚠ Line 9 | 203.0.113.7 | Directory traversal attempt
⚠ Line 10 | 203.0.113.7 | Possible XSS attempt 

## Lab: Vulnerability Scanning with Nmap

**Target:** scanme.nmap.org (authorized Nmap testing server)
**Tool:** Nmap 7.99 with vulners NSE script

**Findings:**
- OpenSSH 6.6.1p1 — outdated version, multiple known CVEs including 
  CVE-2016-6515 (DoS, CVSS 7.8)
- Apache httpd 2.4.7 — outdated version, multiple known CVEs including 
  CVE-2014-0226 (race condition, CVSS 6.8)
- Possible CSRF vulnerability detected on search forms (no token found)
- Directory listing enabled on /images/

**Takeaway:** Both services are running versions from ~2014, which is a common 
real-world finding in VAPT engagements — demonstrates the importance of patch 
management. The CSRF finding directly informed my own Secure Cloud Storage 
project, where I implemented Flask-WTF CSRF tokens on all forms.

markdown
## Tech Stack
Python, socket, concurrent.futures (threading), re (regex), argparse, colorama

## Author
Sneha Yelpulwar — B.Tech CSE, cybersecurity enthusiast
