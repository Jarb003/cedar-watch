"""
log_store.py
SQLite persistence layer for parsed log events and alerts — this is what
turns Cedar Watch from a "re-parse the file every time" tool into something
closer to a real SIEM, where ingested data sticks around and can be searched
or charted without re-reading the source log.

The database lives at the project root as cedar_watch.db (created on first
use). Each log LINE is unique in the events table, so re-scanning the same
file (or live-tailing it) never creates duplicate rows — this is what makes
it safe to call insert_events() repeatedly, e.g. once per live-tail poll.

Usage (as a library):
    import log_store
    log_store.insert_events(events)
    log_store.insert_alerts(alerts)
    rows = log_store.query_events(ip="203.0.113.45")
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "cedar_watch.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    event_type TEXT NOT NULL,
    username TEXT NOT NULL,
    ip TEXT NOT NULL,
    port TEXT,
    raw_line TEXT NOT NULL UNIQUE,
    ingested_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule TEXT NOT NULL,
    severity TEXT NOT NULL,
    ip TEXT NOT NULL,
    detail TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE(rule, ip, detail)
);

CREATE INDEX IF NOT EXISTS idx_events_ip ON events(ip);
CREATE INDEX IF NOT EXISTS idx_events_username ON events(username);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);

-- Real-time PC activity (netwatch_events.py): Windows logons, new processes,
-- USB/removable drive connects. Separate from `events` above because this
-- data doesn't have the username/ip/port shape that SSH log lines do.
CREATE TABLE IF NOT EXISTS system_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    category TEXT NOT NULL,     -- "logon", "process", or "usb"
    subtype TEXT NOT NULL,      -- e.g. "success"/"failure"; a process name; a drive letter
    source TEXT,                -- account name, executable path, or drive path (context-dependent)
    detail TEXT NOT NULL,
    risk TEXT NOT NULL,         -- "info", "low", "medium", "high"
    raw_key TEXT NOT NULL UNIQUE,
    ingested_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sysevents_category ON system_events(category);
CREATE INDEX IF NOT EXISTS idx_sysevents_timestamp ON system_events(timestamp);

-- Cached AbuseIPDB lookups (threat_intel.py). Reputation doesn't change
-- minute to minute, and the free API tier is capped at 1,000 checks/day, so
-- results are cached here and only re-fetched once they go stale.
CREATE TABLE IF NOT EXISTS threat_intel_cache (
    ip TEXT PRIMARY KEY,
    abuse_score INTEGER NOT NULL,
    total_reports INTEGER NOT NULL,
    country TEXT,
    isp TEXT,
    is_whitelisted INTEGER NOT NULL,
    checked_at TEXT NOT NULL
);
"""


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    try:
        conn.executescript(_SCHEMA)
        conn.commit()
    finally:
        conn.close()


def insert_events(events):
    """
    Stores parsed LogEvent objects. Returns the number of NEW rows inserted
    (rows skipped due to the raw_line UNIQUE constraint don't count).
    """
    if not events:
        return 0
    init_db()
    conn = get_connection()
    inserted = 0
    try:
        for e in events:
            cur = conn.execute(
                """INSERT OR IGNORE INTO events
                   (timestamp, event_type, username, ip, port, raw_line, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    e.timestamp.isoformat(),
                    e.event_type,
                    e.username,
                    e.ip,
                    e.port,
                    e.raw_line,
                    datetime.now().isoformat(),
                ),
            )
            if cur.rowcount:
                inserted += 1
        conn.commit()
    finally:
        conn.close()
    return inserted


def insert_alerts(alerts):
    """
    Stores Alert objects. Identical (rule, ip, detail) alerts are only stored
    once. Returns the subset of `alerts` that were actually new (useful for
    live-tail, which recomputes detectors over a rolling window every poll
    and only wants to surface alerts it hasn't already reported).
    """
    if not alerts:
        return []
    init_db()
    conn = get_connection()
    newly_inserted = []
    try:
        for a in alerts:
            cur = conn.execute(
                """INSERT OR IGNORE INTO alerts (rule, severity, ip, detail, created_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (a.rule, a.severity, a.ip, a.detail, datetime.now().isoformat()),
            )
            if cur.rowcount:
                newly_inserted.append(a)
        conn.commit()
    finally:
        conn.close()
    return newly_inserted


def query_events(ip=None, username=None, event_type=None, start=None, end=None, limit=500):
    """
    Searches stored events with optional filters. start/end are datetime
    objects (inclusive) or None. Returns a list of sqlite3.Row (dict-like).
    """
    init_db()
    conn = get_connection()
    try:
        clauses = []
        params = []

        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if username:
            clauses.append("username = ?")
            params.append(username)
        if event_type:
            clauses.append("event_type = ?")
            params.append(event_type)
        if start:
            clauses.append("timestamp >= ?")
            params.append(start.isoformat())
        if end:
            clauses.append("timestamp <= ?")
            params.append(end.isoformat())

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def top_ips(limit=5, event_type="failed_login"):
    """Returns [(ip, count), ...] sorted by count descending."""
    init_db()
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT ip, COUNT(*) as cnt FROM events
               WHERE event_type = ?
               GROUP BY ip ORDER BY cnt DESC LIMIT ?""",
            (event_type, limit),
        ).fetchall()
        return [(r["ip"], r["cnt"]) for r in rows]
    finally:
        conn.close()


def events_per_hour(event_type="failed_login"):
    """Returns [(hour_bucket, count), ...] for a simple time-series chart."""
    init_db()
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT substr(timestamp, 1, 13) as hour_bucket, COUNT(*) as cnt
               FROM events WHERE event_type = ?
               GROUP BY hour_bucket ORDER BY hour_bucket ASC""",
            (event_type,),
        ).fetchall()
        return [(r["hour_bucket"], r["cnt"]) for r in rows]
    finally:
        conn.close()


def alert_severity_counts():
    """Returns {severity: count} across all stored alerts."""
    init_db()
    conn = get_connection()
    try:
        rows = conn.execute("SELECT severity, COUNT(*) as cnt FROM alerts GROUP BY severity").fetchall()
        return {r["severity"]: r["cnt"] for r in rows}
    finally:
        conn.close()


def total_counts():
    """Quick summary: total events, total alerts, distinct IPs seen."""
    init_db()
    conn = get_connection()
    try:
        events_total = conn.execute("SELECT COUNT(*) as c FROM events").fetchone()["c"]
        alerts_total = conn.execute("SELECT COUNT(*) as c FROM alerts").fetchone()["c"]
        distinct_ips = conn.execute("SELECT COUNT(DISTINCT ip) as c FROM events").fetchone()["c"]
        return {"events": events_total, "alerts": alerts_total, "distinct_ips": distinct_ips}
    finally:
        conn.close()


def clear_all():
    """Wipes all stored events and alerts. Useful for demos/testing."""
    init_db()
    conn = get_connection()
    try:
        conn.execute("DELETE FROM events")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM system_events")
        conn.commit()
    finally:
        conn.close()


def insert_system_events(sys_events):
    """
    Stores SystemEvent objects (see netwatch_events.py). Returns the subset
    that were actually new, same dedup pattern as insert_alerts — each event
    carries its own raw_key so callers control what counts as "the same
    event again" (e.g. a process's pid+create_time, a drive's device path).
    """
    if not sys_events:
        return []
    init_db()
    conn = get_connection()
    newly_inserted = []
    try:
        for e in sys_events:
            cur = conn.execute(
                """INSERT OR IGNORE INTO system_events
                   (timestamp, category, subtype, source, detail, risk, raw_key, ingested_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    e.timestamp.isoformat(), e.category, e.subtype, e.source,
                    e.detail, e.risk, e.raw_key, datetime.now().isoformat(),
                ),
            )
            if cur.rowcount:
                newly_inserted.append(e)
        conn.commit()
    finally:
        conn.close()
    return newly_inserted


def query_system_events(category=None, risk=None, limit=500):
    """Searches stored system events with optional filters, most recent first."""
    init_db()
    conn = get_connection()
    try:
        clauses = []
        params = []
        if category:
            clauses.append("category = ?")
            params.append(category)
        if risk:
            clauses.append("risk = ?")
            params.append(risk)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"SELECT * FROM system_events {where} ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_threat_intel(ip):
    """Returns the cached AbuseIPDB result for an IP as a dict, or None if never checked."""
    init_db()
    conn = get_connection()
    try:
        row = conn.execute("SELECT * FROM threat_intel_cache WHERE ip = ?", (ip,)).fetchone()
        if not row:
            return None
        result = dict(row)
        result["is_whitelisted"] = bool(result["is_whitelisted"])
        return result
    finally:
        conn.close()


def save_threat_intel(result):
    """
    Upserts a threat-intel result (keyed by IP) — `result` is the dict shape
    returned by threat_intel.check_ip(): ip, abuse_score, total_reports,
    country, isp, is_whitelisted, checked_at.
    """
    init_db()
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO threat_intel_cache
               (ip, abuse_score, total_reports, country, isp, is_whitelisted, checked_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET
                   abuse_score=excluded.abuse_score,
                   total_reports=excluded.total_reports,
                   country=excluded.country,
                   isp=excluded.isp,
                   is_whitelisted=excluded.is_whitelisted,
                   checked_at=excluded.checked_at""",
            (
                result["ip"], result["abuse_score"], result["total_reports"],
                result["country"], result["isp"], int(result["is_whitelisted"]),
                result["checked_at"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
