"""
netwatch_portscan.py
A blue-team-style port scanner: checks devices on your LAN for open TCP ports
and flags the ones that are commonly considered risky on an everyday endpoint
(Telnet, SMB, RDP exposed to the whole LAN, database ports, etc.).

This is a "quick posture check" scan, similar in spirit to `nmap -F` (fast
scan of common ports) rather than a full 1-65535 sweep. Good for spotting
services you didn't know were listening, not a full pentest tool.

Usage:
    python src/netwatch_portscan.py               # scans every device found on your LAN
    python src/netwatch_portscan.py 192.168.1.42   # scans just one host
"""

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import netwatch_local_network as lnw

# port -> (service name, is_risky_on_a_normal_endpoint)
COMMON_PORTS = {
    21:    ("FTP", True),
    22:    ("SSH", False),
    23:    ("Telnet", True),
    25:    ("SMTP", False),
    53:    ("DNS", False),
    80:    ("HTTP", False),
    110:   ("POP3", False),
    111:   ("RPCbind", True),
    135:   ("MS RPC", True),
    139:   ("NetBIOS", True),
    143:   ("IMAP", False),
    443:   ("HTTPS", False),
    445:   ("SMB", True),
    993:   ("IMAPS", False),
    995:   ("POP3S", False),
    1433:  ("MS SQL", True),
    1521:  ("Oracle DB", True),
    3306:  ("MySQL", True),
    3389:  ("RDP", True),
    5000:  ("UPnP / dev server", True),
    5432:  ("PostgreSQL", True),
    5900:  ("VNC", True),
    5985:  ("WinRM (HTTP)", True),
    5986:  ("WinRM (HTTPS)", True),
    6379:  ("Redis", True),
    8080:  ("HTTP-alt", False),
    8443:  ("HTTPS-alt", False),
    27017: ("MongoDB", True),
}


def _is_broadcast_or_multicast(ip):
    return ip.endswith(".255") or ip == "255.255.255.255" or ip.startswith("224.") or ip.startswith("239.")


def discover_targets():
    """Finds live devices on the LAN by reusing the local-network sweep/ARP logic."""
    own_ip = lnw.get_own_ip()
    lnw.sweep_subnet(own_ip)
    raw = lnw.get_arp_table()
    devices = lnw.parse_arp_table(raw)

    ips = set()
    for d in devices:
        ip = d["ip"]
        if _is_broadcast_or_multicast(ip):
            continue
        ips.add(ip)
    return sorted(ips, key=lambda ip: tuple(int(p) for p in ip.split(".")))


def _check_port(ip, port, timeout):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_hosts(ips, ports=None, timeout=0.4, max_workers=200):
    """
    Checks every (ip, port) pair concurrently. Returns {ip: [open_port, ...]}.
    Flattening all hosts x ports into one thread pool (rather than looping
    host-by-host) is what makes scanning a whole /24 in a reasonable time
    feasible with a plain connect-scan.
    """
    ports = ports or list(COMMON_PORTS.keys())
    results = {ip: [] for ip in ips}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(_check_port, ip, port, timeout): (ip, port)
            for ip in ips
            for port in ports
        }
        for future in as_completed(future_to_target):
            ip, port = future_to_target[future]
            if future.result():
                results[ip].append(port)

    for ip in results:
        results[ip].sort()
    return results


def print_report(target=None):
    print("=" * 80)
    print("  PORT SCAN — BLUE TEAM POSTURE CHECK")
    print("=" * 80)

    if target:
        ips = [target]
        print(f"Target: {target}\n")
    else:
        print("Discovering devices on your network...")
        ips = discover_targets()
        if not ips:
            print("No devices found. Try running the Local Network scan first.")
            return
        print(f"Found {len(ips)} device(s) to scan.\n")

    print(f"Checking {len(COMMON_PORTS)} common ports per host — this may take a moment...\n")
    results = scan_hosts(ips, list(COMMON_PORTS.keys()))

    risky_hosts = []
    for ip in ips:
        open_ports = results.get(ip, [])
        self_tag = "  <- THIS IS YOU" if ip == lnw.get_own_ip() else ""
        print(f"{ip}{self_tag}")

        if not open_ports:
            print("    No open ports found among the ones checked.\n")
            continue

        host_is_risky = False
        for port in open_ports:
            service, risky = COMMON_PORTS.get(port, ("Unknown", False))
            flag = "  [!] RISKY — verify this is intentional" if risky else ""
            print(f"    {port:<6} open   {service:<18}{flag}")
            if risky:
                host_is_risky = True
        if host_is_risky:
            risky_hosts.append(ip)
        print()

    print("=" * 80)
    if risky_hosts:
        print(f"[!] {len(risky_hosts)} device(s) have ports open that are commonly considered risky:")
        for ip in risky_hosts:
            print(f"    - {ip}")
        print()
        print("  Not automatically a problem, but on a normal end-user PC, ports like")
        print("  Telnet, SMB, RDP, or database services being reachable from the LAN")
        print("  are worth double-checking — especially if you didn't set them up")
        print("  yourself, or don't recognize the device.")
    else:
        print("No commonly-risky ports found open on the scanned device(s).")

    print()
    print("Note: this checks a curated list of common ports, similar to nmap's fast")
    print("scan (-F), not a full 1-65535 sweep. It's meant for a quick posture check,")
    print("not exhaustive enumeration.")


if __name__ == "__main__":
    import sys
    target_arg = sys.argv[1] if len(sys.argv) > 1 else None
    print_report(target_arg)
