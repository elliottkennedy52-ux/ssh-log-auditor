#!/usr/bin/env python3
"""
Linux SSH Authentication & Brute-Force Log Auditor
Parses /var/log/auth.log, /var/log/secure, or journalctl SSH output to detect
failed login spikes, brute-force IP sources, targeted usernames, and successful logins.
"""

import argparse
import json
import re
import subprocess
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

FAILED_PATTERN = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)
ACCEPTED_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
)

SAMPLE_LOGS = """Nov 22 01:14:02 ubuntu-prod sshd[1421]: Failed password for invalid user admin from 185.220.101.42 port 51234 ssh2
Nov 22 01:14:05 ubuntu-prod sshd[1421]: Failed password for invalid user admin from 185.220.101.42 port 51238 ssh2
Nov 22 01:14:09 ubuntu-prod sshd[1421]: Failed password for root from 185.220.101.42 port 51245 ssh2
Nov 22 01:14:12 ubuntu-prod sshd[1421]: Failed password for root from 185.220.101.42 port 51250 ssh2
Nov 22 01:14:16 ubuntu-prod sshd[1421]: Failed password for invalid user ubuntu from 185.220.101.42 port 51255 ssh2
Nov 22 01:14:20 ubuntu-prod sshd[1421]: Failed password for root from 45.33.32.156 port 44120 ssh2
Nov 22 01:14:25 ubuntu-prod sshd[1421]: Failed password for invalid user deploy from 45.33.32.156 port 44129 ssh2
Nov 22 01:15:01 ubuntu-prod sshd[1489]: Accepted publickey for elliott from 10.0.14.25 port 60112 ssh2
Nov 22 01:18:44 ubuntu-prod sshd[1502]: Accepted password for root from 185.220.101.42 port 51900 ssh2
"""


def read_logs(log_path: str | None, use_demo: bool) -> list[str]:
    """Load SSH log lines from demo dataset, file path, or systemd journalctl."""
    if use_demo:
        return SAMPLE_LOGS.strip().splitlines()

    if log_path:
        path = Path(log_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {log_path}")
        return path.read_text(encoding="utf-8", errors="ignore").splitlines()

    for default_file in ("/var/log/auth.log", "/var/log/secure"):
        path = Path(default_file)
        if path.exists():
            return path.read_text(encoding="utf-8", errors="ignore").splitlines()

    result = subprocess.run(
        ["journalctl", "-u", "sshd", "--no-pager", "-n", "2000"],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.splitlines()


def analyze_logs(lines: list[str], threshold: int) -> dict:
    """Parse log lines and flag suspicious IP activity above threshold."""
    failed_by_ip: Counter = Counter()
    failed_by_user: Counter = Counter()
    targeted_users_per_ip: defaultdict[str, set[str]] = defaultdict(set)
    accepted_logins: list[dict[str, str]] = []

    for line in lines:
        if match := FAILED_PATTERN.search(line):
            user = match.group("user")
            ip = match.group("ip")
            failed_by_ip[ip] += 1
            failed_by_user[user] += 1
            targeted_users_per_ip[ip].add(user)
        elif match := ACCEPTED_PATTERN.search(line):
            accepted_logins.append({"user": match.group("user"), "ip": match.group("ip")})

    flagged_ips = [
        {
            "ip": ip,
            "failed_attempts": count,
            "targeted_users": sorted(targeted_users_per_ip[ip]),
            "compromise_alert": any(a["ip"] == ip for a in accepted_logins),
        }
        for ip, count in failed_by_ip.most_common()
        if count >= threshold
    ]

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "total_lines_scanned": len(lines),
        "total_failed_attempts": sum(failed_by_ip.values()),
        "total_accepted_logins": len(accepted_logins),
        "threshold": threshold,
        "flagged_brute_force_ips": flagged_ips,
        "top_targeted_usernames": dict(failed_by_user.most_common(10)),
        "accepted_sessions": accepted_logins,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Linux SSH Authentication Log & Brute-Force Auditor"
    )
    parser.add_argument("-f", "--file", help="Path to auth.log or secure log file")
    parser.add_argument(
        "-t", "--threshold", type=int, default=5, help="Failed login threshold to flag IPs (default: 5)"
    )
    parser.add_argument(
        "--demo", action="store_true", help="Run against built-in sample SSH attack logs"
    )
    parser.add_argument(
        "-o", "--output", help="Save structured JSON incident report to file"
    )
    args = parser.parse_args()

    lines = read_logs(args.file, args.demo)
    report = analyze_logs(lines, args.threshold)

    print(f"[*] Scanned {report['total_lines_scanned']} log lines")
    print(f"[*] Failed SSH attempts: {report['total_failed_attempts']} | Accepted logins: {report['total_accepted_logins']}")
    print("-" * 60)

    if report["flagged_brute_force_ips"]:
        print(f"[!] FLAGGED SOURCE IPs (>= {args.threshold} failed attempts):")
        for entry in report["flagged_brute_force_ips"]:
            alert = " [CRITICAL: SUBSEQUENT LOGIN SUCCEEDED]" if entry["compromise_alert"] else ""
            print(f"    - {entry['ip']}: {entry['failed_attempts']} failures | Users: {', '.join(entry['targeted_users'])}{alert}")
    else:
        print("[+] No source IPs exceeded the failed-login threshold.")

    if args.output:
        Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] JSON report saved to {args.output}")


if __name__ == "__main__":
    main()
