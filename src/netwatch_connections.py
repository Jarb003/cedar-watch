"""
connections.py
Shows active network connections on your machine — every IP your laptop is
currently talking to (or being contacted by), which process owns the
connection, and a best-effort hostname lookup.

Usage:
    python src/netwatch/connections.py
"""

import socket
import psutil
from datetime import datetime


def resolve_hostname(ip, timeout=0.5):
    """Best-effort reverse DNS lookup. Returns the IP itself if lookup fails."""
    try:
        socket.setdefaulttimeout(timeout)
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None


def is_private_ip(ip):
    """Rough check for private/local IP ranges, so we can flag external vs internal traffic."""
    if ip.startswith(("10.", "192.168.", "127.")):
        return True
    if ip.startswith("172."):
        try:
            second_octet = int(ip.split(".")[1])
            return 16 <= second_octet <= 31
        except (IndexError, ValueError):
            return False
    return False


def get_active_connections(resolve_dns=True):
    """
    Returns a list of dicts describing each active network connection:
    local address, remote address, status, owning process, and whether
    the remote end is external (public internet) or local/private.
    """
    results = []
    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError):
        print("Permission denied reading connections. Try running as Administrator.")
        return results

    for conn in connections:
        if not conn.raddr:
            continue  # skip connections with no remote address (listening sockets)

        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port

        proc_name = "unknown"
        if conn.pid:
            try:
                proc_name = psutil.Process(conn.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                proc_name = f"pid:{conn.pid}"

        hostname = None
        if resolve_dns and not is_private_ip(remote_ip):
            hostname = resolve_hostname(remote_ip)

        results.append({
            "remote_ip": remote_ip,
            "remote_port": remote_port,
            "status": conn.status,
            "process": proc_name,
            "hostname": hostname,
            "external": not is_private_ip(remote_ip),
        })

    return results


def print_report():
    print("=" * 70)
    print("  ACTIVE NETWORK CONNECTIONS")
    print("=" * 70)
    print(f"Captured at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

    conns = get_active_connections()

    if not conns:
        print("No active connections found (or permission denied).")
        return

    external = [c for c in conns if c["external"]]
    internal = [c for c in conns if not c["external"]]

    print(f"Total connections: {len(conns)}  ({len(external)} external, {len(internal)} local)\n")

    if external:
        print("-- EXTERNAL (internet) --")
        for c in external:
            label = c["hostname"] if c["hostname"] else c["remote_ip"]
            print(f"  {c['process']:<20} -> {label:<40} :{c['remote_port']:<6} [{c['status']}]")

    if internal:
        print("\n-- LOCAL / PRIVATE NETWORK --")
        for c in internal:
            print(f"  {c['process']:<20} -> {c['remote_ip']:<40} :{c['remote_port']:<6} [{c['status']}]")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    print_report()
