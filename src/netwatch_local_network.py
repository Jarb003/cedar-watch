"""
local_network.py
Lists devices visible on your local network (same WiFi/LAN) by reading your
machine's ARP table, then enriches each entry with:
  - whether it's YOUR machine
  - whether it's active right now (ping)
  - a best-effort OS/device guess, combining several weak signals

Notes on accuracy:
  - True nmap-style OS fingerprinting crafts raw TCP packets and compares
    header quirks (window size, option ordering, ISN behavior) against a
    huge signature database — that needs raw sockets, admin/root, and is
    well beyond what's practical here. Instead this combines several
    lighter signals the way consumer network scanners (Fing, Advanced IP
    Scanner) do:
      1. Hostname (reverse DNS) — if your router hands out a DHCP hostname
         like "Johns-iPhone" or "DESKTOP-4ERGH97", that's the strongest and
         most direct signal, so it's checked first.
      2. MAC vendor (from api.macvendors.com) — Apple's OUI block means
         iPhone/Mac, Samsung's means Android, a router manufacturer's OUI
         means network gear, etc.
      3. Targeted open ports (via netwatch_portscan) — RDP/SMB/RPC open
         strongly suggests Windows, AFP suggests Mac, SSH suggests Linux/Mac.
      4. Ping TTL — the roughest signal (Windows~128, Linux/Mac/mobile~64,
         network gear~255), used only when nothing else matched.
    Every guess in the report says which signal it came from, since this is
    still fundamentally a best-effort heuristic, not a certainty.

Usage:
    python src/netwatch_local_network.py
"""

import re
import time
import socket
import platform
import threading
import subprocess
import ipaddress
from concurrent.futures import ThreadPoolExecutor

import requests

import netwatch_portscan

# Ports worth checking specifically because their presence hints at an OS,
# on top of whatever netwatch_portscan's own security-focused scan covers.
OS_SIGNAL_PORTS = [22, 135, 445, 548, 3389, 62078]


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


def _quick_ping(ip, timeout_ms=300):
    """Fires a single fast, low-timeout ping — used only to populate the ARP cache during a sweep."""
    system = platform.system()
    if system == "Windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    try:
        subprocess.run(cmd, capture_output=True, timeout=2)
    except (subprocess.SubprocessError, OSError):
        pass


def sweep_subnet(own_ip, max_workers=40):
    """
    Pings every address in the /24 subnet your machine is on. Most devices
    won't reply (firewalls block ICMP by default on many laptops/phones),
    but the ping still forces your OS to ARP-resolve the address, which
    populates the ARP table even for devices that ignore the ping itself.
    This is why we sweep BEFORE reading arp -a, rather than relying on
    whatever was already cached.
    """
    if not own_ip:
        return
    try:
        network = ipaddress.ip_network(f"{own_ip}/24", strict=False)
    except ValueError:
        return

    targets = [str(ip) for ip in network.hosts()]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(_quick_ping, targets)


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


def resolve_hostname(ip, timeout=0.5):
    """Best-effort reverse DNS lookup. Returns None if the router doesn't hand out DHCP hostnames."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


_vendor_cache = {}
_vendor_lock = threading.Lock()
_last_vendor_call = [0.0]
_VENDOR_MIN_INTERVAL = 1.2  # api.macvendors.com's free tier is rate-limited to roughly 1 req/sec


def get_mac_vendor(mac):
    """
    Best-effort lookup of the device manufacturer from its MAC prefix.
    Thread-safe and globally rate-limited: multiple devices can be looked up
    concurrently, but actual outbound API calls are serialized with a
    minimum gap between them so parallel lookups don't blow through the
    free tier's rate limit. Cached per-MAC so a device is never looked up twice.
    """
    if mac in _vendor_cache:
        return _vendor_cache[mac]

    with _vendor_lock:
        if mac in _vendor_cache:  # re-check: another thread may have filled this while we waited for the lock
            return _vendor_cache[mac]

        elapsed = time.monotonic() - _last_vendor_call[0]
        if elapsed < _VENDOR_MIN_INTERVAL:
            time.sleep(_VENDOR_MIN_INTERVAL - elapsed)

        vendor = None
        try:
            resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=2)
            if resp.status_code == 200:
                vendor = resp.text.strip()
        except requests.RequestException:
            pass

        _last_vendor_call[0] = time.monotonic()
        _vendor_cache[mac] = vendor
        return vendor


def guess_os_combined(ttl, hostname, vendor, open_ports):
    """
    Combines hostname, MAC vendor, open ports, and TTL into one best-effort
    device/OS guess. Returns (guess, source) so callers can show what the
    guess was based on. Checked in order of confidence — hostname first
    (most direct signal, when your router provides one), then vendor+ports,
    then ports alone, and finally the coarse TTL bucket as a last resort.
    """
    hostname_l = (hostname or "").lower()
    vendor_l = (vendor or "").lower()
    open_ports = open_ports or []

    if hostname_l:
        if "iphone" in hostname_l:
            return "iPhone (Apple)", "hostname"
        if "ipad" in hostname_l:
            return "iPad (Apple)", "hostname"
        if any(k in hostname_l for k in ("macbook", "imac", "mac-mini", "mbp", "mac-pro")):
            return "Mac (Apple)", "hostname"
        if any(k in hostname_l for k in ("android", "pixel", "galaxy")):
            return "Android device", "hostname"
        if hostname_l.startswith(("desktop-", "laptop-")) or "-pc" in hostname_l:
            return "Windows PC", "hostname"

    if vendor_l and "apple" in vendor_l:
        if 62078 in open_ports:
            return "iPhone/iPad (Apple, sync port open)", "vendor + open port"
        return "Mac or iOS device (Apple)", "vendor"

    if vendor_l and any(k in vendor_l for k in ("samsung", "huawei", "xiaomi", "oneplus")):
        return "Android device (likely)", "vendor"

    if vendor_l and any(k in vendor_l for k in ("tp-link", "netgear", "asus", "d-link", "ubiquiti", "linksys", "mikrotik", "cisco")):
        return "Router / network device", "vendor"

    if any(p in open_ports for p in (3389, 445, 135)):
        return "Windows (likely)", "open ports (RDP/SMB/RPC)"

    if 548 in open_ports:
        return "Mac (likely)", "open port (AFP)"

    if 22 in open_ports:
        return "Linux/Mac (likely)", "open port (SSH)"

    return guess_os_from_ttl(ttl), "TTL"


def enrich_devices(devices, own_ip, check_active=True, max_workers=16):
    """
    Adds is_self, active, hostname, vendor, open_ports, os_guess, and
    guess_source fields to each device dict.

    Note on "active": if a device appears in the ARP table at all, it has
    communicated on the network recently (that's how ARP works), so we treat
    ARP presence as the primary "active" signal. A direct ping reply, when we
    get one, additionally gives us a TTL to guess the OS — but a failed ping
    does NOT mean the device is offline, since many devices (especially
    Windows laptops and phones) block ICMP by default while still being
    fully connected.
    """
    ips = [d["ip"] for d in devices]

    # One batched port scan across every device (its own thread pool
    # internally) rather than one scan per device — much less overhead.
    open_ports_by_ip = netwatch_portscan.scan_hosts(ips, ports=OS_SIGNAL_PORTS) if check_active else {}

    def enrich_one(d):
        d["is_self"] = (d["ip"] == own_ip)
        d["active"] = True  # presence in the freshly-swept ARP table is the real signal

        if check_active:
            replied, ttl = ping_device(d["ip"])
            d["hostname"] = resolve_hostname(d["ip"])
            d["vendor"] = get_mac_vendor(d["mac"])
            open_ports = open_ports_by_ip.get(d["ip"], [])
            d["open_ports"] = open_ports

            if replied or d["hostname"] or d["vendor"] or open_ports:
                guess, source = guess_os_combined(ttl, d["hostname"], d["vendor"], open_ports)
                d["os_guess"] = guess
                d["guess_source"] = source
            else:
                d["os_guess"] = "Unknown (device doesn't reply to ping)"
                d["guess_source"] = None
        else:
            d["hostname"] = None
            d["vendor"] = None
            d["open_ports"] = []
            d["os_guess"] = "Not checked"
            d["guess_source"] = None
        return d

    # Per-device work (ping + hostname + vendor lookup) is independent, so
    # run it concurrently — vendor lookups stay safe under concurrency
    # because get_mac_vendor() serializes actual API calls internally.
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(enrich_one, devices))

    return devices


def print_report():
    print("=" * 90)
    print("  DEVICES ON YOUR LOCAL NETWORK")
    print("=" * 90)

    own_ip = get_own_ip()
    print(f"Your machine's IP: {own_ip or 'could not determine'}\n")

    print("Scanning your subnet to find all connected devices — this takes ~5-10 seconds...")
    sweep_subnet(own_ip)

    raw = get_arp_table()
    devices = parse_arp_table(raw)

    if not devices:
        print("No devices found, or arp command unavailable on this system.")
        return

    print("Checking device details (hostname, vendor, open ports, OS guess) — this can take 20-30s...\n")
    devices = enrich_devices(devices, own_ip)

    print(f"Found {len(devices)} device(s):\n")
    for d in devices:
        self_tag = "  <- THIS IS YOU" if d["is_self"] else ""
        name = d["hostname"] or d["vendor"] or ""
        name_part = f" [{name}]" if name else ""
        source = f" (via {d['guess_source']})" if d.get("guess_source") else ""
        print(f"  {d['ip']:<16} {d['mac']:<18} {d['os_guess']:<32}{source}{name_part}{self_tag}")

    print("\n" + "=" * 90)
    print("Notes:")
    print("  - All devices listed showed up in your ARP table after an active")
    print("    subnet scan, meaning they're currently on your network.")
    print("  - The OS/device guess combines hostname, MAC vendor, a few targeted")
    print("    open ports, and ping TTL — it's a best-effort heuristic like")
    print("    consumer network scanners use, not a guarantee (real nmap-style")
    print("    fingerprinting needs raw packet crafting well beyond this scope).")
    print("  - Your router's IP (often 192.168.1.1 or 192.168.0.1) is your gateway.")


if __name__ == "__main__":
    print_report()
