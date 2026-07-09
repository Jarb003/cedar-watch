"""
detectors.py
Detection rules that flag suspicious activity from parsed log events.
"""

from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import List

from parser import LogEvent


@dataclass
class Alert:
    rule: str
    severity: str  # "low", "medium", "high"
    ip: str
    detail: str


def detect_brute_force(events: List[LogEvent], threshold: int = 5, window_minutes: int = 5) -> List[Alert]:
    """
    Flags an IP if it has >= threshold failed logins within window_minutes.
    Classic brute-force pattern.
    """
    alerts = []
    failed_by_ip = defaultdict(list)

    for e in events:
        if e.event_type == "failed_login":
            failed_by_ip[e.ip].append(e)

    for ip, attempts in failed_by_ip.items():
        attempts.sort(key=lambda e: e.timestamp)
        window_start = 0
        for i in range(len(attempts)):
            # slide window: drop attempts that fall outside window_minutes from attempts[i]
            while attempts[i].timestamp - attempts[window_start].timestamp > timedelta(minutes=window_minutes):
                window_start += 1
            count_in_window = i - window_start + 1
            if count_in_window >= threshold:
                alerts.append(Alert(
                    rule="brute_force",
                    severity="high",
                    ip=ip,
                    detail=(
                        f"{count_in_window} failed login attempts from {ip} "
                        f"within {window_minutes} minutes (first at {attempts[window_start].timestamp}, "
                        f"latest at {attempts[i].timestamp})"
                    ),
                ))
                break  # one alert per IP is enough, avoid duplicate spam
    return alerts


def detect_username_enumeration(events: List[LogEvent], threshold: int = 3) -> List[Alert]:
    """
    Flags an IP that attempts logins with several DIFFERENT usernames.
    Suggests the attacker is guessing valid accounts rather than brute-forcing one.
    """
    alerts = []
    usernames_by_ip = defaultdict(set)

    for e in events:
        if e.event_type == "failed_login":
            usernames_by_ip[e.ip].add(e.username)

    for ip, usernames in usernames_by_ip.items():
        if len(usernames) >= threshold:
            alerts.append(Alert(
                rule="username_enumeration",
                severity="medium",
                ip=ip,
                detail=f"{len(usernames)} distinct usernames attempted from {ip}: {sorted(usernames)}",
            ))
    return alerts


def detect_unusual_hour_logins(events: List[LogEvent], start_hour: int = 0, end_hour: int = 5) -> List[Alert]:
    """
    Flags SUCCESSFUL logins that occur during unusual hours (default: midnight-5am).
    Successful logins are the ones that matter most here, since a failed unusual-hour
    login is already covered by other rules.
    """
    alerts = []
    for e in events:
        if e.event_type == "accepted_login" and (start_hour <= e.timestamp.hour < end_hour):
            alerts.append(Alert(
                rule="unusual_hour_login",
                severity="medium",
                ip=e.ip,
                detail=f"Successful login for user '{e.username}' from {e.ip} at {e.timestamp} (unusual hour)",
            ))
    return alerts


def run_all_detectors(events: List[LogEvent]) -> List[Alert]:
    """Run every detection rule and return a combined, de-duplicated alert list."""
    alerts = []
    alerts.extend(detect_brute_force(events))
    alerts.extend(detect_username_enumeration(events))
    alerts.extend(detect_unusual_hour_logins(events))
    return alerts
