"""
watch.py
Live monitor mode: tails a log file (like `tail -f`) and runs detection rules
on new events as they arrive, printing alerts in real time.

Usage:
    python src/watch.py sample_logs/auth.log
"""

import sys
import time
import argparse
from collections import deque
from datetime import timedelta

from parser import parse_line
from detectors import run_all_detectors


SEVERITY_COLOR = {
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[94m",
}
RESET = "\033[0m"

# How long to keep events in the sliding window (should cover your longest detection window)
EVENT_RETENTION_MINUTES = 30

# Once an alert fires for a given (rule, ip), don't fire it again for this long
ALERT_COOLDOWN_MINUTES = 10


def tail_file(filepath):
    """
    Generator that yields new lines appended to a file, like `tail -f`.
    Starts reading from the END of the file (only new activity, not history).
    """
    with open(filepath, "r") as f:
        f.seek(0, 2)  # jump to end of file
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def prune_old_events(events, retention_minutes):
    if not events:
        return
    newest = events[-1].timestamp
    while events and (newest - events[0].timestamp) > timedelta(minutes=retention_minutes):
        events.popleft()


def main():
    parser_arg = argparse.ArgumentParser(description="Live-monitor an SSH auth log for suspicious activity.")
    parser_arg.add_argument("logfile", help="Path to the log file to watch")
    args = parser_arg.parse_args()

    print("=" * 60)
    print("  CEDAR WATCH — LIVE MONITOR")
    print("=" * 60)
    print(f"Watching: {args.logfile}")
    print(f"Window: {EVENT_RETENTION_MINUTES} min | Alert cooldown: {ALERT_COOLDOWN_MINUTES} min")
    print("Press Ctrl+C to stop.\n")

    events = deque()
    fired_alerts = {}  # (rule, ip) -> last fired timestamp

    try:
        for line in tail_file(args.logfile):
            event = parse_line(line)
            if not event:
                continue

            events.append(event)
            prune_old_events(events, EVENT_RETENTION_MINUTES)

            alerts = run_all_detectors(list(events))

            for alert in alerts:
                key = (alert.rule, alert.ip)
                last_fired = fired_alerts.get(key)
                now = event.timestamp

                if last_fired and (now - last_fired) < timedelta(minutes=ALERT_COOLDOWN_MINUTES):
                    continue  # still in cooldown, skip

                fired_alerts[key] = now
                color = SEVERITY_COLOR.get(alert.severity, "")
                timestamp_str = now.strftime("%Y-%m-%d %H:%M:%S")
                print(f"{color}[{timestamp_str}] [{alert.severity.upper()}] {alert.rule}{RESET}")
                print(f"  {alert.detail}\n")

    except KeyboardInterrupt:
        print("\n\nStopped watching. Goodbye.")
        sys.exit(0)
    except FileNotFoundError:
        print(f"Error: file not found: {args.logfile}")
        sys.exit(1)


if __name__ == "__main__":
    main()
