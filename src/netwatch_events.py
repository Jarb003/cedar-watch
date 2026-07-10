"""
netwatch_events.py
Real-time monitoring of YOUR PC's own activity — the "live SIEM feed" idea
applied to a personal machine instead of a server. Three independent
sources; any one can fail or be unavailable without breaking the others:

  - Logon events: reads Windows' actual Security Event Log via PowerShell's
    Get-WinEvent (Event ID 4624 = successful logon, 4625 = failed logon).
    Querying the Security log requires Administrator privileges — if you're
    not elevated, this source reports itself unavailable (via
    logon_events_available()) instead of silently failing forever.
  - New processes: polls running processes (via psutil, already a
    dependency) and reports newly started ones. Flags execution from
    Temp/Downloads, or a process NAMED like a core Windows process but not
    actually running from System32 — a classic malware disguise trick —
    as elevated risk.
  - USB / removable drives: polls disk partitions (via psutil) and reports
    newly connected/disconnected removable drives.

Usage:
    watcher = EventWatcher(on_update=my_callback)
    watcher.start()
    ...
    watcher.stop()

`on_update(new_events, error)` is called from the background thread — GUI
callers must hop back to the main thread (e.g. Tkinter's root.after()).
"""

import re
import json
import subprocess
import threading
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

import psutil

import log_store


@dataclass
class SystemEvent:
    timestamp: datetime
    category: str       # "logon", "process", "usb"
    subtype: str
    source: Optional[str]
    detail: str
    risk: str            # "info", "low", "medium", "high"
    raw_key: str


# ---------------------------------------------------------------------------
# Logon events (Windows Security Event Log)
# ---------------------------------------------------------------------------

_LOGON_EVENT_IDS = "4624,4625"


def logon_events_available():
    """
    Checks whether we can actually query the Security log (requires
    Administrator). Returns (True, None) or (False, reason). Call this once
    when a watcher starts so the GUI can explain *why* logon events aren't
    showing up, rather than treating every empty poll as "nothing happened."
    """
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop | Out-Null; Write-Output OK"],
            capture_output=True, text=True, timeout=10,
        )
        if "OK" in result.stdout:
            return True, None
        reason = result.stderr.strip() or "Could not query the Security log (likely needs Administrator)."
        return False, reason
    except FileNotFoundError:
        return False, "PowerShell not found."
    except subprocess.TimeoutExpired:
        return False, "Timed out querying the Security log."
    except OSError as e:
        return False, str(e)


def get_logon_events(minutes_back=5):
    """
    Fetches recent logon events (4624/4625) from the Windows Security log.
    Returns a list of SystemEvent. Any failure (not admin, PowerShell
    missing, no matching events, etc.) just returns an empty list — use
    logon_events_available() separately to distinguish "nothing happened"
    from "can't read this at all."
    """
    ps_command = (
        f"$events = Get-WinEvent -FilterHashtable @{{LogName='Security'; "
        f"Id={_LOGON_EVENT_IDS}; StartTime=(Get-Date).AddMinutes(-{minutes_back})}} "
        f"-ErrorAction SilentlyContinue; "
        f"$events | Select-Object Id, "
        f"@{{Name='TimeCreated';Expression={{$_.TimeCreated.ToString('o')}}}}, "
        f"@{{Name='Message';Expression={{$_.Message}}}} | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_command],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return []

    raw = result.stdout.strip()
    if not raw:
        return []

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if isinstance(data, dict):  # a single matching event comes back as a dict, not a list
        data = [data]

    events = []
    for item in data:
        event_id = item.get("Id")
        message = item.get("Message", "") or ""
        timestamp = _parse_ps_datetime(item.get("TimeCreated"))

        account = _extract_field(message, "Account Name:")
        source_ip = _extract_field(message, "Source Network Address:")
        location = f" from {source_ip}" if source_ip and source_ip != "-" else ""

        if event_id == 4624:
            subtype, risk = "success", "info"
            detail = f"Successful logon for '{account or 'unknown'}'{location}"
        elif event_id == 4625:
            subtype, risk = "failure", "medium"
            detail = f"Failed logon attempt for '{account or 'unknown'}'{location}"
        else:
            continue

        raw_key = f"logon:{event_id}:{item.get('TimeCreated')}:{account}:{source_ip}"
        events.append(SystemEvent(
            timestamp=timestamp, category="logon", subtype=subtype,
            source=account, detail=detail, risk=risk, raw_key=raw_key,
        ))

    return events


def _extract_field(message, label):
    """
    Pulls a 'Label:    value' line out of a Get-WinEvent Message block.
    Returns the LAST match, not the first: 4624/4625 messages repeat
    "Account Name:" in multiple sections (Subject, then New Logon / Account
    For Which Logon Failed), and the Subject block is usually blank ("-") or
    the machine account (SYSTEM) — the account that actually matters always
    comes later in the message.
    """
    match = None
    for line in message.splitlines():
        line = line.strip()
        if line.startswith(label):
            match = line[len(label):].strip() or None
    return match


def _parse_ps_datetime(value):
    """Parses the ISO-8601 string we explicitly requested via .ToString('o')."""
    if not value:
        return datetime.now()
    try:
        # datetime.fromisoformat chokes on more than 6 fractional digits (.NET gives 7)
        cleaned = re.sub(r"(\.\d{6})\d*", r"\1", value)
        return datetime.fromisoformat(cleaned)
    except ValueError:
        return datetime.now()


# ---------------------------------------------------------------------------
# New process launches
# ---------------------------------------------------------------------------

SUSPICIOUS_PATH_MARKERS = ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\", "/tmp/")
COMMON_SYSTEM_PROCESS_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
    "explorer.exe", "smss.exe", "wininit.exe",
}
EXPECTED_SYSTEM_DIR_MARKER = "\\windows\\system32\\"


def snapshot_processes():
    """Returns {pid: (name, exe_path, create_time)} for all currently running processes."""
    snapshot = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "create_time"]):
        try:
            info = proc.info
            snapshot[info["pid"]] = (info.get("name") or "", info.get("exe") or "", info.get("create_time"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return snapshot


def diff_new_processes(previous_snapshot, current_snapshot):
    """
    Returns SystemEvents for PIDs present now but not in the previous
    snapshot. Flags processes running from Temp/Downloads (medium risk), and
    processes named after core Windows processes but NOT running from
    System32 (high risk — a common way malware hides in plain sight).
    """
    events = []
    for pid in set(current_snapshot) - set(previous_snapshot):
        name, exe, create_time = current_snapshot[pid]
        exe_lower = exe.lower()
        reasons = []
        risk = "info"

        if any(marker in exe_lower for marker in SUSPICIOUS_PATH_MARKERS):
            risk = "medium"
            reasons.append("running from a Temp/Downloads folder")

        if name.lower() in COMMON_SYSTEM_PROCESS_NAMES and EXPECTED_SYSTEM_DIR_MARKER not in exe_lower:
            risk = "high"
            reasons.append("named like a core Windows process but not running from System32")

        detail = f"New process: {name} (pid {pid})" + (f" — {exe}" if exe else "")
        if reasons:
            detail += f" [{'; '.join(reasons)}]"

        events.append(SystemEvent(
            timestamp=datetime.now(), category="process", subtype=name or "unknown",
            source=exe or None, detail=detail, risk=risk,
            raw_key=f"process:{pid}:{create_time}",
        ))
    return events


# ---------------------------------------------------------------------------
# USB / removable drives
# ---------------------------------------------------------------------------

def snapshot_removable_drives():
    """Returns {device: mountpoint} for currently connected removable drives."""
    drives = {}
    try:
        partitions = psutil.disk_partitions()
    except OSError:
        return drives
    for p in partitions:
        opts = (p.opts or "").lower()
        if "removable" in opts or "cdrom" in opts:
            drives[p.device] = p.mountpoint
    return drives


def diff_removable_drives(previous_snapshot, current_snapshot):
    """Returns SystemEvents for removable drives that connected or disconnected."""
    events = []
    now = datetime.now()

    for device in set(current_snapshot) - set(previous_snapshot):
        mountpoint = current_snapshot[device]
        events.append(SystemEvent(
            timestamp=now, category="usb", subtype="connected", source=device,
            detail=f"Removable drive connected: {device} ({mountpoint})",
            risk="low", raw_key=f"usb-connect:{device}:{now.isoformat()}",
        ))

    for device in set(previous_snapshot) - set(current_snapshot):
        events.append(SystemEvent(
            timestamp=now, category="usb", subtype="disconnected", source=device,
            detail=f"Removable drive disconnected: {device}",
            risk="info", raw_key=f"usb-disconnect:{device}:{now.isoformat()}",
        ))

    return events


# ---------------------------------------------------------------------------
# Combined watcher
# ---------------------------------------------------------------------------

class EventWatcher:
    """
    Polls all three PC-activity sources on a background thread and reports
    newly-stored SystemEvents via a callback. Process/USB checks run every
    poll (cheap); logon events run less often since each check spawns a
    PowerShell process (comparatively slow).
    """

    def __init__(self, on_update=None, poll_interval=3.0, logon_poll_every_n_polls=10):
        self.on_update = on_update
        self.poll_interval = poll_interval
        self.logon_poll_every_n_polls = logon_poll_every_n_polls

        self._stop_event = threading.Event()
        self._thread = None

        self.logon_available = None
        self.logon_unavailable_reason = None

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _watch_loop(self):
        self.logon_available, self.logon_unavailable_reason = logon_events_available()

        process_snapshot = snapshot_processes()
        drive_snapshot = snapshot_removable_drives()
        poll_count = 0

        while not self._stop_event.is_set():
            poll_count += 1
            all_events = []

            current_processes = snapshot_processes()
            all_events.extend(diff_new_processes(process_snapshot, current_processes))
            process_snapshot = current_processes

            current_drives = snapshot_removable_drives()
            all_events.extend(diff_removable_drives(drive_snapshot, current_drives))
            drive_snapshot = current_drives

            if self.logon_available and poll_count % self.logon_poll_every_n_polls == 0:
                minutes_back = max(1, int((self.poll_interval * self.logon_poll_every_n_polls) / 60) + 1)
                all_events.extend(get_logon_events(minutes_back=minutes_back))

            if all_events:
                new_events = log_store.insert_system_events(all_events)
                if new_events and self.on_update:
                    self.on_update(new_events, None)

            self._stop_event.wait(self.poll_interval)
