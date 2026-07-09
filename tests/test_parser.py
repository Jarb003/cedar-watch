"""
Basic unit tests for parser.py and detectors.py.
Run with: python -m pytest tests/  (from the project root, after adding src to PYTHONPATH)
or simply: python tests/test_parser.py
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from parser import parse_line
from detectors import detect_brute_force, detect_username_enumeration


def test_parse_failed_login():
    line = "Jul  8 02:14:01 webserver sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "failed_login"
    assert event.username == "admin"
    assert event.ip == "203.0.113.45"
    print("test_parse_failed_login passed")


def test_parse_accepted_login():
    line = "Jul  8 09:32:10 webserver sshd[1050]: Accepted password for jarb003 from 192.168.1.20 port 60321 ssh2"
    event = parse_line(line)
    assert event is not None
    assert event.event_type == "accepted_login"
    assert event.username == "jarb003"
    print("test_parse_accepted_login passed")


def test_parse_unrelated_line_returns_none():
    line = "Jul  8 09:32:10 webserver sshd[1050]: pam_unix(sshd:session): session opened for user jarb003 by (uid=0)"
    event = parse_line(line)
    assert event is None
    print("test_parse_unrelated_line_returns_none passed")


def test_brute_force_detection():
    lines = [
        f"Jul  8 02:14:0{i} webserver sshd[100{i}]: Failed password for invalid user admin from 203.0.113.45 port 5142{i} ssh2"
        for i in range(6)
    ]
    events = [parse_line(l) for l in lines]
    events = [e for e in events if e]
    alerts = detect_brute_force(events, threshold=5, window_minutes=5)
    assert len(alerts) == 1
    assert alerts[0].ip == "203.0.113.45"
    print("test_brute_force_detection passed")


def test_username_enumeration_detection():
    users = ["admin", "root", "test", "guest"]
    lines = [
        f"Jul  8 02:1{i}:00 webserver sshd[100{i}]: Failed password for invalid user {u} from 198.51.100.9 port 5142{i} ssh2"
        for i, u in enumerate(users)
    ]
    events = [parse_line(l) for l in lines]
    events = [e for e in events if e]
    alerts = detect_username_enumeration(events, threshold=3)
    assert len(alerts) == 1
    print("test_username_enumeration_detection passed")


if __name__ == "__main__":
    test_parse_failed_login()
    test_parse_accepted_login()
    test_parse_unrelated_line_returns_none()
    test_brute_force_detection()
    test_username_enumeration_detection()
    print("\nAll tests passed.")
