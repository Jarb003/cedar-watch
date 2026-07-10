"""
main.py
CLI entry point for the log analyzer.

Usage:
    python src/main.py sample_logs/auth.log
"""

import sys
import argparse
from collections import Counter

from parser import parse_log_file
from detectors import run_all_detectors
import threat_intel


SEVERITY_COLOR = {
    "high": "\033[91m",    # red
    "medium": "\033[93m",  # yellow
    "low": "\033[94m",     # blue
}
RESET = "\033[0m"


def print_report(events, alerts):
    print("=" * 60)
    print("  LOG ANALYSIS REPORT")
    print("=" * 60)

    print(f"\nTotal events parsed: {len(events)}")
    failed = sum(1 for e in events if e.event_type == "failed_login")
    accepted = sum(1 for e in events if e.event_type == "accepted_login")
    print(f"  Failed logins:   {failed}")
    print(f"  Accepted logins: {accepted}")

    print(f"\nAlerts triggered: {len(alerts)}")
    print("-" * 60)

    if not alerts:
        print("No suspicious activity detected.")
    else:
        # sort so high severity shows first
        severity_order = {"high": 0, "medium": 1, "low": 2}
        alerts_sorted = sorted(alerts, key=lambda a: severity_order.get(a.severity, 3))
        for a in alerts_sorted:
            color = SEVERITY_COLOR.get(a.severity, "")
            print(f"{color}[{a.severity.upper()}] {a.rule}{RESET}")
            print(f"  {a.detail}\n")

    print("-" * 60)
    top_ips = Counter(e.ip for e in events if e.event_type == "failed_login").most_common(5)
    if top_ips:
        print("\nTop offending IPs (by failed login count):")
        for ip, count in top_ips:
            print(f"  {ip}: {count} failed attempts")

    print("\n" + "=" * 60)


def main():
    parser_arg = argparse.ArgumentParser(description="Analyze SSH auth logs for suspicious activity.")
    parser_arg.add_argument("logfile", help="Path to the auth log file to analyze")
    args = parser_arg.parse_args()

    try:
        events = parse_log_file(args.logfile)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}")
        sys.exit(1)

    if not events:
        print("No parseable log events found. Check the log format.")
        sys.exit(0)

    alerts = run_all_detectors(events)

    if threat_intel.is_configured():
        print("Checking failed-login IPs against AbuseIPDB threat intel...")
        alerts += threat_intel.generate_threat_intel_alerts(events)
    else:
        print("(No AbuseIPDB API key configured in config.py — skipping threat intel checks.)")

    print_report(events, alerts)


if __name__ == "__main__":
    main()
