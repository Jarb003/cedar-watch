"""
local_network.py
Lists devices visible on your local network (same WiFi/LAN) by reading your
machine's ARP table, then enriches each entry with:
  - whether it's YOUR machine
  - whether it's active right now (ping)
  - a best-effort OS guess (from ping TTL)
  - the device manufacturer (from the MAC address vendor lookup)

Notes on accuracy:
  - OS guess is a heuristic based on TTL, not a guarantee. Windows devices
    typically reply with TTL ~128, Linux/Mac/mobile devices ~64, and
    routers/network gear often ~255. This is the same trick tools like
    nmap use for a "quick guess" — it's right most of the time on a home
    network but not foolproof (VPNs, custom TTLs, etc. can throw it off).
  - Vendor lookup identifies the manufacturer of the network chip (e.g.
    "Apple, Inc." or "TP-Link"), which is a strong hint but not a direct
    OS reading — a MacBook and an iPhone are both "Apple, Inc."
  - Vendor lookup requires internet access (queries api.macvendors.com)
    and is rate-limited on the free tier; failures fall back gracefully.

Usage:
    python src/netwatch_local_network.py
"""

import re
import socket
import platform
import subprocess

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def get_own_ip():
    """Returns this machine's local IP address on the active network interface."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))  # doesn't actually send anything, just picks the right interface
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except socket.gaierror:
            return None
    finally:
        s.close()


def get_arp_table():
    """Runs the OS's arp command and returns raw output."""
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=10)
        return result.stdout
    except (subprocess.SubprocessError, FileNotFoundError):
        return ""


def parse_arp_table(raw_output):
    """Parses arp -a output into a list of dicts with ip and mac address."""
    devices = []
    windows_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F-]{17})\s+(\w+)")
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


def ping_device(ip, timeout_ms=800):
    """
    Pings a device once. Returns (is_active, ttl).
    Cross-platform: uses the right ping flags for Windows vs Unix.
    """
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        active = result.returncode == 0
        ttl_match = re.search(r"[Tt][Tt][Ll][=:](\d+)", result.stdout)
        ttl = int(ttl_match.group(1)) if ttl_match else None
        return active, ttl
    except (subprocess.SubprocessError, OSError):
        return False, None


def guess_os_from_ttl(ttl):
    """
    Rough OS family guess based on initial TTL value.
    Common starting TTLs: Linux/Mac/mobile = 64, Windows = 128, routers/network gear = 255.
    We compare the observed (decremented) TTL against the nearest ceiling.
    """
    if ttl is None:
        return "Unknown (no reply)"
    if ttl <= 64:
        return "Linux / macOS / mobile (Unix-like)"
    elif ttl <= 128:
        return "Windows"
    else:
        return "Router / network device"


_vendor_cache = {}


def get_mac_vendor(mac):
    """Best-effort lookup of the device manufacturer from its MAC address prefix."""
    if not HAS_REQUESTS:
        return None
    if mac in _vendor_cache:
        return _vendor_cache[mac]
    try:
        resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
        if resp.status_code == 200:
            vendor = resp.text.strip()
            _vendor_cache[mac] = vendor
            return vendor
    except requests.RequestException:
        pass
    return None


def enrich_devices(devices, own_ip, check_active=True, lookup_vendor=True):
    """Adds is_self, active, os_guess, and vendor fields to each device dict."""
    for d in devices:
        d["is_self"] = (d["ip"] == own_ip)

        if check_active:
            active, ttl = ping_device(d["ip"])
            d["active"] = active
            d["os_guess"] = guess_os_from_ttl(ttl) if active else "Unknown (offline)"
        else:
            d["active"] = None
            d["os_guess"] = "Not checked"

        d["vendor"] = get_mac_vendor(d["mac"]) if lookup_vendor else None

    return devices


def print_report():
    print("=" * 80)
    print("  DEVICES ON YOUR LOCAL NETWORK")
    print("=" * 80)
    print("(from your machine's ARP table, enriched with live ping + vendor lookup)\n")

    own_ip = get_own_ip()
    print(f"Your machine's IP: {own_ip or 'could not determine'}\n")

    raw = get_arp_table()
    devices = parse_arp_table(raw)

    if not devices:
        print("No devices found, or arp command unavailable on this system.")
        return

    print("Pinging devices to check who's active — this may take a few seconds...\n")
    devices = enrich_devices(devices, own_ip)

    print(f"Found {len(devices)} device(s):\n")
    for d in devices:
        self_tag = "  <- THIS IS YOU" if d["is_self"] else ""
        status = "ACTIVE" if d["active"] else ("OFFLINE" if d["active"] is False else "?")
        vendor = d["vendor"] or "unknown vendor"

        print(f"  {d['ip']:<16} {d['mac']:<18} [{status:<7}] {d['os_guess']:<32} {vendor}{self_tag}")

    print("\n" + "=" * 80)
    print("Notes:")
    print("  - OS guess is a heuristic (based on ping TTL), not a certainty.")
    print("  - Vendor identifies the network chip maker, not necessarily the OS")
    print("    (e.g. a MacBook and an iPhone both show as 'Apple, Inc.').")
    print("  - Your router's IP (often 192.168.1.1 or 192.168.0.1) is your gateway.")
    print("  - Any device here you don't recognize is worth investigating.")


if __name__ == "__main__":
    print_report()