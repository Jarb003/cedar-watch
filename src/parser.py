"""
parser.py
Parses SSH auth log lines into structured events.

Expected log format (standard Linux /var/log/auth.log style):
Jul  8 02:14:01 webserver sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2
Jul  8 09:32:10 webserver sshd[1050]: Accepted password for jarb003 from 192.168.1.20 port 60321 ssh2
"""

import re
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List


@dataclass
class LogEvent:
    timestamp: datetime
    event_type: str      # "failed_login" or "accepted_login"
    username: str
    ip: str
    port: Optional[str] = None
    raw_line: str = ""


# Matches both "Failed password for invalid user X" and "Failed password for X"
FAILED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)

ACCEPTED_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+"
    r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port (?P<port>\d+)"
)

# Log lines don't include a year, so we assume current year for timestamp parsing
CURRENT_YEAR = datetime.now().year


def parse_line(line: str) -> Optional[LogEvent]:
    """Parse a single log line into a LogEvent, or return None if it doesn't match."""
    match = FAILED_RE.match(line)
    if match:
        return LogEvent(
            timestamp=_parse_timestamp(match.group("ts")),
            event_type="failed_login",
            username=match.group("user"),
            ip=match.group("ip"),
            port=match.group("port"),
            raw_line=line.strip(),
        )

    match = ACCEPTED_RE.match(line)
    if match:
        return LogEvent(
            timestamp=_parse_timestamp(match.group("ts")),
            event_type="accepted_login",
            username=match.group("user"),
            ip=match.group("ip"),
            port=match.group("port"),
            raw_line=line.strip(),
        )

    return None


def _parse_timestamp(ts_str: str) -> datetime:
    """Convert 'Jul  8 02:14:01' style timestamp into a datetime object."""
    # Collapse double spaces (single-digit days use double space in real logs)
    ts_str = re.sub(r"\s+", " ", ts_str.strip())
    return datetime.strptime(f"{ts_str} {CURRENT_YEAR}", "%b %d %H:%M:%S %Y")


def parse_log_file(filepath: str) -> List[LogEvent]:
    """Read a log file and return a list of parsed LogEvents (skips unparseable lines)."""
    events = []
    with open(filepath, "r") as f:
        for line in f:
            event = parse_line(line)
            if event:
                events.append(event)
    return events
