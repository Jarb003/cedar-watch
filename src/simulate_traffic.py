"""
simulate_traffic.py
Appends synthetic SSH log lines to a log file over time, simulating live traffic
(including a brute-force burst) so you can test watch.py's live monitoring.

Usage:
    python src/simulate_traffic.py sample_logs/auth.log

Run this in one terminal, and `python src/watch.py sample_logs/auth.log` in another
to see alerts fire live.
"""

import sys
import time
import argparse
from datetime import datetime

NORMAL_USERS = ["jarb003", "admin_backup", "deploy"]
NORMAL_IPS = ["192.168.1.20", "192.168.1.55", "10.0.0.12"]

ATTACKER_IP = "185.220.101.7"
ATTACKER_USERNAMES = ["admin", "root", "test", "guest", "oracle", "postgres"]


def log_line(event_type, username, ip, port):
    ts = datetime.now().strftime("%b %e %H:%M:%S")
    if event_type == "failed":
        return f"{ts} webserver sshd[{port}]: Failed password for invalid user {username} from {ip} port {port} ssh2\n"
    else:
        return f"{ts} webserver sshd[{port}]: Accepted password for {username} from {ip} port {port} ssh2\n"


def main():
    parser_arg = argparse.ArgumentParser(description="Simulate live SSH traffic for testing watch.py")
    parser_arg.add_argument("logfile", help="Path to the log file to append to")
    parser_arg.add_argument("--burst-after", type=int, default=10,
                             help="Seconds of normal traffic before the brute-force burst starts")
    args = parser_arg.parse_args()

    print(f"Simulating traffic into {args.logfile} ... Ctrl+C to stop.")
    print(f"Normal traffic first, brute-force burst begins after ~{args.burst_after}s.\n")

    port = 40000
    elapsed = 0

    try:
        with open(args.logfile, "a") as f:
            # Phase 1: normal traffic
            while elapsed < args.burst_after:
                user = NORMAL_USERS[port % len(NORMAL_USERS)]
                ip = NORMAL_IPS[port % len(NORMAL_IPS)]
                line = log_line("accepted", user, ip, port)
                f.write(line)
                f.flush()
                print(f"  wrote: {line.strip()}")
                port += 1
                time.sleep(2)
                elapsed += 2

            # Phase 2: brute-force burst from a single attacker IP
            print("\n  --- starting brute-force burst ---\n")
            for i in range(8):
                user = ATTACKER_USERNAMES[i % len(ATTACKER_USERNAMES)]
                line = log_line("failed", user, ATTACKER_IP, port)
                f.write(line)
                f.flush()
                print(f"  wrote: {line.strip()}")
                port += 1
                time.sleep(1)

            print("\n  --- burst complete, resuming normal traffic ---\n")

            # Phase 3: back to normal traffic
            while True:
                user = NORMAL_USERS[port % len(NORMAL_USERS)]
                ip = NORMAL_IPS[port % len(NORMAL_IPS)]
                line = log_line("accepted", user, ip, port)
                f.write(line)
                f.flush()
                print(f"  wrote: {line.strip()}")
                port += 1
                time.sleep(3)

    except KeyboardInterrupt:
        print("\nStopped simulating traffic.")
        sys.exit(0)


if __name__ == "__main__":
    main()
