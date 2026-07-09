"""
local_network.py
Lists devices visible on your local network (same WiFi/LAN) by reading your
machine's ARP table — the list of devices your laptop has recently
communicated with at the network level.

Note: this only shows devices your laptop has already talked to (e.g. the
router, other devices that sent traffic your way). For a full active scan of
every device on the network, a dedicated tool like nmap is more thorough,
but this requires no extra installation and works cross-platform.

Usage:
    python src/netwatch_local_network.py
"""

import subprocess
import platform
import re


def get_arp_table():
    """Runs the OS's arp command and returns raw output."""
    system = platform.system()
    try:
        if system == "Windows":
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        else:
            result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def parse_arp_table(raw_output):
    """
    Parses arp -a output into a list of dicts with ip and mac address.
    Handles both Windows and Unix-style arp output formats.
    """
    devices = []

    # Windows format:   192.168.1.1      00-14-22-01-23-45     dynamic
    windows_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)")

    # Unix format: ? (192.168.1.1) at 00:14:22:01:23:45 [ether] on en0
    unix_pattern = re.compile(r"\(([\d.]+)\)\s+at\s+([0-9a-fA-F:]{17})")

    for line in raw_output.splitlines():
        match = windows_pattern.search(line)
        if match:
            devices.append({"ip": match.group(1), "mac": match.group(2), "type": match.group(3)})
            continue

        match = unix_pattern.search(line)
        if match:
            devices.append({"ip": match.group(1), "mac": match.group(2), "type": "dynamic"})

    return devices


def print_report():
    print("=" * 70)
    print("  DEVICES ON YOUR LOCAL NETWORK")
    print("=" * 70)
    print("(from your machine's ARP table — devices it has recently talked to)\n")

    raw = get_arp_table()
    devices = parse_arp_table(raw)

    if not devices:
        print("No devices found, or arp command unavailable on this system.")
        return

    print(f"Found {len(devices)} device(s):\n")
    for d in devices:
        print(f"  {d['ip']:<18} {d['mac']:<20} [{d['type']}]")

    print("\n" + "=" * 70)
    print("Tip: your router's IP (often 192.168.1.1 or 192.168.0.1) is your")
    print("gateway. Any unfamiliar device MAC here is worth investigating.")


if __name__ == "__main__":
    print_report()
