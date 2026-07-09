# Cedar Watch

A lightweight SSH auth log analyzer that detects suspicious login activity — brute-force attempts, username enumeration, and logins at unusual hours.

Built as a portfolio project to demonstrate log parsing, pattern-based threat detection, and basic blue-team analysis.

## Why this exists

Most intrusion attempts on internet-facing servers show up first in auth logs, long before they show up anywhere else. Manually scanning thousands of log lines doesn't scale. This tool automates the first pass: parse the log, flag what looks abnormal, rank it by severity.

## What it detects

| Rule | Description | Severity |
|---|---|---|
| **Brute force** | 5+ failed logins from the same IP within a 5-minute window | High |
| **Username enumeration** | 3+ distinct usernames attempted from the same IP | Medium |
| **Unusual hour login** | Successful login between midnight and 5am | Medium |

## Desktop app (simple UI)

If you'd rather click buttons than type commands, there's a Tkinter desktop app with tabs for everything above:

```bash
python src/gui.py
```

No extra install needed for the UI itself (Tkinter ships with Python). Tabs:
- **Log Analyzer** — pick a log file, click Scan
- **Connections** — click Scan to see active network connections
- **Browser History** — pick Chrome or Edge, click Load History
- **Local Network** — click Scan to list devices on your WiFi/LAN

## Netwatch: personal network activity monitor

Beyond server logs, Cedar Watch also monitors your own machine's network activity:

```bash
pip install -r requirements.txt   # installs psutil
python src/netwatch.py            # full report: connections + history + local network
```

Or run each piece individually:

```bash
python src/netwatch.py --connections-only   # who your laptop is talking to right now
python src/netwatch.py --history-only       # your recent browser history (Chrome/Edge)
python src/netwatch.py --network-only       # other devices on your WiFi/LAN
```

**What each part shows:**
- **Connections** (`netwatch_connections.py`) — every active network connection on your machine, which process owns it, and whether the remote end is external (internet) or local. Flags anything talking to an unfamiliar external IP.
- **Browser history** (`netwatch_browser_history.py`) — reads your Chrome or Edge history directly from its local SQLite database (`--browser edge` to switch).
- **Local network** (`netwatch_local_network.py`) — reads your machine's ARP table to list other devices on the same WiFi/LAN it has recently talked to (your router, phone, smart devices, etc.) — useful for spotting an unfamiliar device on your network.

## Usage

```bash
python src/main.py sample_logs/auth.log
```

Sample output:

```
============================================================
  LOG ANALYSIS REPORT
============================================================

Total events parsed: 31
  Failed logins:   27
  Accepted logins: 4

Alerts triggered: 4
------------------------------------------------------------
[HIGH] brute_force
  5 failed login attempts from 203.0.113.45 within 5 minutes ...

[MEDIUM] username_enumeration
  6 distinct usernames attempted from 203.0.113.45: [...]
------------------------------------------------------------

Top offending IPs (by failed login count):
  203.0.113.45: 11 failed attempts
  45.33.32.156: 8 failed attempts
```

## Live monitor mode

Instead of a one-time scan, `watch.py` tails a log file continuously (like `tail -f`) and prints alerts the moment suspicious activity happens:

```bash
python src/watch.py sample_logs/auth.log
```

To test it without a real server under attack, run the traffic simulator in a second terminal — it writes normal login activity followed by a simulated brute-force burst:

```bash
python src/simulate_traffic.py sample_logs/auth.log
```

Watch mode uses a 30-minute sliding window for detection and a 10-minute cooldown per (rule, IP) pair, so an ongoing attack triggers one alert rather than flooding your terminal every second.

## Running it on your own logs

This parser expects standard Linux SSH auth log format (`/var/log/auth.log` on Debian/Ubuntu, `/var/log/secure` on RHEL/CentOS):

```
Jul  8 02:14:01 hostname sshd[1001]: Failed password for invalid user admin from 203.0.113.45 port 51422 ssh2
```

If your log format differs, adjust the regex patterns in `src/parser.py`.

## Project structure

```
cedar-watch/
├── src/
│   ├── parser.py           # Regex-based log line parsing
│   ├── detectors.py        # Detection rules (brute force, enumeration, unusual hours)
│   ├── main.py             # CLI entry point: one-time scan and report
│   ├── watch.py            # Live monitor: tails a log and alerts in real time
│   ├── simulate_traffic.py # Generates synthetic traffic to test watch.py
│   ├── gui.py               # Simple Tkinter desktop UI (all features, tabbed)
│   ├── netwatch.py          # Combined CLI: connections + browser history + local network
│   ├── netwatch_connections.py
│   ├── netwatch_browser_history.py
│   └── netwatch_local_network.py
├── sample_logs/
│   └── auth.log         # Synthetic sample data for testing
├── tests/
│   └── test_parser.py   # Unit tests
└── requirements.txt
```

## Design decisions

- **No external dependencies for core logic** — parsing and detection use only the Python standard library, so the tool runs anywhere without setup friction.
- **Sliding window for brute-force detection** rather than fixed time buckets, to avoid missing attacks that straddle a bucket boundary (e.g. 4 attempts at 02:04 + 4 at 02:06 would be missed by naive per-minute bucketing).
- **One alert per IP per rule**, not one per event, to keep the report readable instead of flooding it with duplicate warnings for the same ongoing attack.

## Roadmap / ideas for extending this

- Cross-reference flagged IPs against a threat intel feed (e.g. AbuseIPDB API)
- Add geo-IP lookups to flag logins from unexpected countries
- Support Apache/Nginx access log format in addition to SSH
- Persist results to SQLite for historical trend tracking
- Simple Flask/Streamlit dashboard for visualizing alerts over time

## License

MIT
