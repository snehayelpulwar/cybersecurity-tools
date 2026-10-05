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


## Tech Stack
Python, socket, concurrent.futures (threading), argparse, colorama

## Author
Sneha Yelpulwar — B.Tech CSE, cybersecurity enthusiast