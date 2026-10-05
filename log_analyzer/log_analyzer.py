"""
Log File Analyzer
Scans a log file (e.g. web server access log or SSH auth log) and flags
suspicious patterns: repeated failed logins, high request rates from one IP,
and known attack signatures in URLs.

Works with:
- Apache/Nginx-style access logs (one line per request)
- Linux auth.log style lines containing "Failed password"
"""

import re
import sys
import argparse
from collections import defaultdict
from colorama import Fore, Style, init

init(autoreset=True)

# Patterns that commonly indicate an attack attempt in a URL or log line
SUSPICIOUS_PATTERNS = [
    (r"\.\./", "Directory traversal attempt"),
    (r"(?i)union.{1,20}select", "Possible SQL injection"),
    (r"(?i)<script", "Possible XSS attempt"),
    (r"(?i)/etc/passwd", "Attempt to read system file"),
    (r"(?i)select.{1,20}from", "Possible SQL injection"),
    (r"(?i)wp-admin|wp-login", "WordPress admin scanning"),
    (r"(?i)\.(php|asp|jsp)\d?\?.*=", "Possible code injection via parameter"),
]

# An IP matching this regex is extracted from most common log formats
IP_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

FAILED_LOGIN_PATTERN = re.compile(r"(?i)failed password|authentication failure|invalid user")


def analyze_log(filepath, fail_threshold=5, request_threshold=100):
    ip_fail_counts = defaultdict(int)
    ip_request_counts = defaultdict(int)
    suspicious_lines = []
    total_lines = 0

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                total_lines += 1
                ip_match = IP_PATTERN.search(line)
                ip = ip_match.group(1) if ip_match else "unknown"

                ip_request_counts[ip] += 1

                if FAILED_LOGIN_PATTERN.search(line):
                    ip_fail_counts[ip] += 1

                for pattern, description in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line):
                        suspicious_lines.append((line_num, ip, description, line.strip()[:100]))
                        break
    except FileNotFoundError:
        print(f"{Fore.RED}Error: file '{filepath}' not found.{Style.RESET_ALL}")
        sys.exit(1)

    return {
        "total_lines": total_lines,
        "ip_fail_counts": ip_fail_counts,
        "ip_request_counts": ip_request_counts,
        "suspicious_lines": suspicious_lines,
        "fail_threshold": fail_threshold,
        "request_threshold": request_threshold,
    }


def print_report(results):
    print(f"\n{Fore.CYAN}{'=' * 60}")
    print(f"LOG ANALYSIS REPORT")
    print(f"{'=' * 60}{Style.RESET_ALL}")
    print(f"Total lines scanned: {results['total_lines']}\n")

    # --- Brute force / repeated failed logins ---
    flagged_fails = {ip: count for ip, count in results["ip_fail_counts"].items()
                     if count >= results["fail_threshold"]}
    print(f"{Fore.YELLOW}[Repeated failed logins]{Style.RESET_ALL} "
         f"(threshold: {results['fail_threshold']}+)")
    if flagged_fails:
        for ip, count in sorted(flagged_fails.items(), key=lambda x: -x[1]):
            print(f"  {Fore.RED}⚠{Style.RESET_ALL}  {ip:<16} — {count} failed attempts "
                 f"{Fore.RED}(possible brute force){Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}None found.{Style.RESET_ALL}")

    # --- High request volume (possible scanning / DoS) ---
    flagged_requests = {ip: count for ip, count in results["ip_request_counts"].items()
                        if count >= results["request_threshold"]}
    print(f"\n{Fore.YELLOW}[High request volume]{Style.RESET_ALL} "
         f"(threshold: {results['request_threshold']}+ requests)")
    if flagged_requests:
        for ip, count in sorted(flagged_requests.items(), key=lambda x: -x[1]):
            print(f"  {Fore.RED}⚠{Style.RESET_ALL}  {ip:<16} — {count} requests "
                 f"{Fore.RED}(possible scanning/DoS){Style.RESET_ALL}")
    else:
        print(f"  {Fore.GREEN}None found.{Style.RESET_ALL}")

    # --- Known attack signatures ---
    print(f"\n{Fore.YELLOW}[Suspicious request patterns]{Style.RESET_ALL}")
    if results["suspicious_lines"]:
        for line_num, ip, description, snippet in results["suspicious_lines"][:20]:
            print(f"  {Fore.RED}⚠{Style.RESET_ALL}  Line {line_num} | {ip:<16} | {description}")
            print(f"      {snippet}")
        if len(results["suspicious_lines"]) > 20:
            print(f"  ... and {len(results['suspicious_lines']) - 20} more")
    else:
        print(f"  {Fore.GREEN}None found.{Style.RESET_ALL}")

    print(f"\n{Fore.CYAN}{'=' * 60}{Style.RESET_ALL}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Analyze a log file for suspicious activity."
    )
    parser.add_argument("logfile", help="Path to the log file to analyze")
    parser.add_argument("--fail-threshold", type=int, default=5,
                        help="Failed logins from one IP to flag as brute force (default: 5)")
    parser.add_argument("--request-threshold", type=int, default=100,
                        help="Requests from one IP to flag as high volume (default: 100)")
    args = parser.parse_args()

    results = analyze_log(args.logfile, args.fail_threshold, args.request_threshold)
    print_report(results)


if __name__ == "__main__":
    main()