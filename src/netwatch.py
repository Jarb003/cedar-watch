"""
netwatch.py
Combined personal network activity report:
  1. Active connections — who your laptop is talking to right now
  2. Browser history — sites you've recently visited
  3. Local network — other devices on your WiFi/LAN

Usage:
    python src/netwatch.py                    # everything
    python src/netwatch.py --connections-only
    python src/netwatch.py --history-only --browser edge
    python src/netwatch.py --network-only
"""

import argparse

import netwatch_connections
import netwatch_browser_history
import netwatch_local_network


def main():
    parser = argparse.ArgumentParser(description="Personal network activity report.")
    parser.add_argument("--connections-only", action="store_true", help="Only show active connections")
    parser.add_argument("--history-only", action="store_true", help="Only show browser history")
    parser.add_argument("--network-only", action="store_true", help="Only show local network devices")
    parser.add_argument("--browser", choices=["chrome", "edge"], default="chrome")
    parser.add_argument("--limit", type=int, default=30, help="Number of browser history entries")
    args = parser.parse_args()

    show_all = not (args.connections_only or args.history_only or args.network_only)

    if show_all or args.connections_only:
        netwatch_connections.print_report()
        print()

    if show_all or args.history_only:
        netwatch_browser_history.print_report(args.browser, args.limit)
        print()

    if show_all or args.network_only:
        netwatch_local_network.print_report()


if __name__ == "__main__":
    main()
