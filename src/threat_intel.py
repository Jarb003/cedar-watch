"""
threat_intel.py
Checks IP addresses against AbuseIPDB — a public database of IPs reported
for malicious activity (SSH brute-forcing, port scanning, spam, botnets,
etc.). This turns "203.0.113.45 failed to log in 8 times" into "this IP is
a known attacker reported 400 times in the last 90 days" — the kind of
context a real SOC analyst pulls up during triage instead of just staring
at a bare address.

Requires a free API key from https://www.abuseipdb.com/account/api, stored
in config.py at the project root (gitignored — never commit your key; see
config.example.py for the expected format). Without a key configured, every
function here degrades gracefully to "no data" rather than erroring, so the
rest of the app works fine without threat intel set up.

Results are cached in the database (log_store.py) for CACHE_TTL_HOURS,
since IP reputation doesn't meaningfully change minute to minute and the
free API tier is capped at 1,000 checks/day.

Usage:
    result = check_ip("203.0.113.45")
    if result and result["abuse_score"] >= 50:
        print(f"known malicious IP: {result['total_reports']} reports")
"""

import os
import sys
from datetime import datetime, timedelta

import requests

import log_store
from detectors import Alert

# config.py lives at the project root (one level up from src/), not in src/
# itself — since scripts run as `python src/gui.py`, Python only puts src/
# on sys.path by default, so the project root needs to be added explicitly
# before `import config` can find it there.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from config import ABUSEIPDB_API_KEY
except ImportError:
    ABUSEIPDB_API_KEY = ""

API_URL = "https://api.abuseipdb.com/api/v2/check"
CACHE_TTL_HOURS = 24
HIGH_RISK_THRESHOLD = 50  # abuse confidence score (0-100) that triggers an alert


def is_configured():
    """Whether an API key has been set in config.py."""
    return bool(ABUSEIPDB_API_KEY and ABUSEIPDB_API_KEY.strip())


def check_ip(ip, force_refresh=False):
    """
    Returns a dict — {ip, abuse_score, total_reports, country, isp,
    is_whitelisted, checked_at} — or None if no API key is configured, the
    IP is private/reserved (AbuseIPDB has no data for those anyway), or the
    lookup fails for any reason (network error, rate limit, bad key, etc.).

    Uses a cached result when one exists and is under CACHE_TTL_HOURS old,
    unless force_refresh=True.
    """
    if not is_configured():
        return None
    if _is_private_or_reserved(ip):
        return None

    if not force_refresh:
        cached = log_store.get_threat_intel(ip)
        if cached and _is_fresh(cached["checked_at"]):
            return cached

    try:
        response = requests.get(
            API_URL,
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=8,
        )
    except requests.RequestException:
        return None

    if response.status_code != 200:
        return None

    try:
        data = response.json()["data"]
    except (ValueError, KeyError):
        return None

    result = {
        "ip": ip,
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode") or "unknown",
        "isp": data.get("isp") or "unknown",
        "is_whitelisted": bool(data.get("isWhitelisted")),
        "checked_at": datetime.now().isoformat(),
    }
    log_store.save_threat_intel(result)
    return result


def generate_threat_intel_alerts(events):
    """
    For each distinct failed-login IP in a list of LogEvents, checks
    AbuseIPDB and returns an Alert for any IP at or above
    HIGH_RISK_THRESHOLD. Returns [] immediately (no API calls at all) if no
    key is configured — purely additive on top of the existing rule-based
    detectors, and safe to call unconditionally.
    """
    if not is_configured():
        return []

    alerts = []
    checked_ips = set()
    for e in events:
        if e.event_type != "failed_login" or e.ip in checked_ips:
            continue
        checked_ips.add(e.ip)

        result = check_ip(e.ip)
        if result and result["abuse_score"] >= HIGH_RISK_THRESHOLD:
            alerts.append(Alert(
                rule="known_malicious_ip",
                severity="high",
                ip=e.ip,
                detail=(
                    f"{e.ip} is a known malicious IP on AbuseIPDB: "
                    f"{result['abuse_score']}% abuse confidence, "
                    f"{result['total_reports']} report(s), "
                    f"{result['country']} ({result['isp']})"
                ),
            ))
    return alerts


def _is_fresh(checked_at_str):
    try:
        checked_at = datetime.fromisoformat(checked_at_str)
    except (ValueError, TypeError):
        return False
    return datetime.now() - checked_at < timedelta(hours=CACHE_TTL_HOURS)


def _is_private_or_reserved(ip):
    """Skip lookups for private/local IPs — there's no public reputation data for these."""
    if ip.startswith(("10.", "192.168.", "127.", "169.254.")):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            return 16 <= second <= 31
        except (IndexError, ValueError):
            return False
    return False
