"""
log_tail.py
Live log tailing — watches a log file for newly appended lines the way
`tail -f` does, instead of scanning the whole file once and stopping. Every
poll, new lines get parsed, stored in the database (log_store), and checked
against a rolling window of recent events so brute-force / enumeration
patterns are caught as they happen, not just on a one-off scan.

Usage:
    tailer = LogTailer("sample_logs/auth.log", on_update=my_callback)
    tailer.start()
    ...
    tailer.stop()

`on_update(new_events, new_alerts, error)` is called from the BACKGROUND
THREAD, not the main thread — callers driving a GUI must hop back onto the
main thread themselves (e.g. via Tkinter's root.after()) before touching
any widgets.
"""

import os
import threading
from datetime import datetime

import log_store
import threat_intel
from parser import parse_line
from detectors import run_all_detectors


class LogTailer:
    def __init__(self, filepath, on_update=None, poll_interval=1.0, window_size=500):
        self.filepath = filepath
        self.on_update = on_update
        self.poll_interval = poll_interval
        self.window_size = window_size  # how many recent events to keep for live detection

        self._stop_event = threading.Event()
        self._thread = None
        self._recent_events = []

    def is_running(self):
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running():
            return
        self._stop_event.clear()
        self._recent_events = []
        self._thread = threading.Thread(target=self._watch_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _watch_loop(self):
        try:
            f = open(self.filepath, "r")
        except OSError as e:
            if self.on_update:
                self.on_update([], [], f"Could not open file: {e}")
            return

        with f:
            # Start at the END of the file — like `tail -f`, we only react to
            # lines appended AFTER live tailing began, not the whole history
            # (the one-off "Scan Log" button already covers historical data).
            f.seek(0, os.SEEK_END)
            last_pos = f.tell()

            while not self._stop_event.is_set():
                try:
                    current_size = os.path.getsize(self.filepath)
                except OSError:
                    current_size = last_pos

                # File got smaller than where we left off — it was truncated
                # or rotated. Restart from the beginning rather than erroring.
                if current_size < last_pos:
                    f.seek(0)
                    last_pos = 0

                new_lines = f.readlines()
                last_pos = f.tell()

                if new_lines:
                    new_events = [e for e in (parse_line(line) for line in new_lines) if e]

                    if new_events:
                        log_store.insert_events(new_events)

                        self._recent_events.extend(new_events)
                        self._recent_events = self._recent_events[-self.window_size:]

                        candidate_alerts = run_all_detectors(self._recent_events)
                        if threat_intel.is_configured():
                            # Cached per-IP for 24h, so this is a cheap local
                            # DB read on every poll after the first real check.
                            candidate_alerts += threat_intel.generate_threat_intel_alerts(new_events)
                        new_alerts = log_store.insert_alerts(candidate_alerts)

                        if self.on_update:
                            self.on_update(new_events, new_alerts, None)

                self._stop_event.wait(self.poll_interval)
