"""
Simple TCP Port Scanner (multithreaded)
Scans a target host for open ports in a given range.

IMPORTANT: Only scan hosts you own or have explicit written permission
to test. Scanning systems without authorization may be illegal.
"""

import socket
import sys
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init

init(autoreset=True)

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    445: "SMB", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
}


def scan_port(target, port, timeout=0.5):
    """Try to open a TCP connection to one port. Return (port, is_open)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        result = sock.connect_ex((target, port))  # 0 means the port accepted the connection
        return port, (result == 0)
    except socket.error:
        return port, False
    finally:
        sock.close()


def resolve_target(target):
    """Turn a hostname into an IP address, or confirm an IP is valid."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"{Fore.RED}Error: could not resolve hostname '{target}'{Style.RESET_ALL}")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a host for open TCP ports. For authorized testing only."
    )
    parser.add_argument("target", help="Hostname or IP address to scan")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range, e.g. 1-1024 or 80,443,8080 (default: 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=0.5,
                        help="Timeout per port in seconds (default: 0.5)")
    parser.add_argument("-w", "--workers", type=int, default=200,
                        help="Number of ports to check at the same time (default: 200)")
    args = parser.parse_args()

    ip = resolve_target(args.target)

    if "-" in args.ports:
        start, end = args.ports.split("-")
        ports_to_scan = list(range(int(start), int(end) + 1))
    else:
        ports_to_scan = [int(p) for p in args.ports.split(",")]

    print(f"\n{Fore.CYAN}{'=' * 50}")
    print(f"Scanning target: {args.target} ({ip})")
    print(f"Port range: {args.ports}  |  Workers: {args.workers}")
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'=' * 50}{Style.RESET_ALL}\n")

    open_ports = []
    start_time = datetime.now()

    # ThreadPoolExecutor checks many ports in parallel instead of one by one,
    # which is why this version finishes in seconds instead of minutes.
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(scan_port, ip, port, args.timeout)
                  for port in ports_to_scan]

        results = {}
        for future in as_completed(futures):
            port, is_open = future.result()
            results[port] = is_open

    for port in sorted(ports_to_scan):
        if results.get(port):
            service = COMMON_PORTS.get(port, "unknown")
            print(f"{Fore.GREEN}[OPEN]{Style.RESET_ALL}   Port {port:<6} ({service})")
            open_ports.append(port)

    duration = (datetime.now() - start_time).total_seconds()

    print(f"\n{Fore.CYAN}{'=' * 50}")
    print(f"Scan complete in {duration:.2f} seconds")
    print(f"Open ports found: {len(open_ports)}")
    if open_ports:
        print(f"Ports: {', '.join(str(p) for p in open_ports)}")
    print(f"{'=' * 50}{Style.RESET_ALL}\n")


if __name__ == "__main__":
    main()