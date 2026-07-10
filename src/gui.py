"""
gui.py
Simple desktop UI for Cedar Watch. Tabs for:
  - Log Analyzer (scan an SSH auth log file)
  - Connections (who your laptop is talking to)
  - Browser History (recent sites visited)
  - Local Network (devices on your WiFi/LAN)
  - Port Scan (blue-team check for risky open ports on your LAN)
  - PC Activity (live feed of YOUR machine's logons, new processes, USB drives)
  - Search (query stored log events by IP / username / type / time)
  - Dashboard (charts summarizing everything ingested so far)

Log Analyzer scans are stored in a local SQLite database (log_store.py), so
Search and Dashboard have data to work with, and repeat scans / live tailing
don't lose history. Live Tail watches the log file for new lines in real
time instead of requiring a re-scan.

Uses the Python standard library for the UI (tkinter) plus matplotlib for
the Dashboard tab's charts.

Usage:
    python src/gui.py
"""

import io
import contextlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
from datetime import datetime

from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import netwatch_connections
import netwatch_browser_history
import netwatch_local_network
import netwatch_portscan
import log_store
import dashboard
from log_tail import LogTailer
from netwatch_events import EventWatcher
import threat_intel
from parser import parse_log_file
from detectors import run_all_detectors
import main as log_main


class CedarWatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cedar Watch")
        self.root.geometry("820x560")
        self.root.configure(bg="#1e2a1e")

        self._setup_style()

        self.tailer = None          # LogTailer instance, created when Live Tail is started
        self.event_watcher = None   # EventWatcher instance, created when PC Activity monitoring starts

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.log_tab = self._build_log_tab(notebook)
        self.conn_tab = self._build_connections_tab(notebook)
        self.history_tab = self._build_history_tab(notebook)
        self.network_tab = self._build_network_tab(notebook)
        self.portscan_tab = self._build_portscan_tab(notebook)
        self.pcactivity_tab = self._build_pcactivity_tab(notebook)
        self.threatintel_tab = self._build_threatintel_tab(notebook)
        self.search_tab = self._build_search_tab(notebook)
        self.dashboard_tab = self._build_dashboard_tab(notebook)

        notebook.add(self.log_tab, text="Log Analyzer")
        notebook.add(self.conn_tab, text="Connections")
        notebook.add(self.history_tab, text="Browser History")
        notebook.add(self.network_tab, text="Local Network")
        notebook.add(self.portscan_tab, text="Port Scan")
        notebook.add(self.pcactivity_tab, text="PC Activity")
        notebook.add(self.threatintel_tab, text="Threat Intel")
        notebook.add(self.search_tab, text="Search")
        notebook.add(self.dashboard_tab, text="Dashboard")

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _setup_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background="#1e2a1e")
        style.configure("TFrame", background="#1e2a1e")
        style.configure("TButton", padding=6)
        style.configure("TLabel", background="#1e2a1e", foreground="#e8f0e8", font=("Segoe UI", 10))

    # ---------- shared helper ----------
    def _make_output_box(self, parent):
        box = scrolledtext.ScrolledText(
            parent, wrap="word", bg="#0f170f", fg="#c8e6c8",
            insertbackground="#c8e6c8", font=("Consolas", 9), relief="flat"
        )
        box.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        return box

    def _run_captured(self, box, func, *args, **kwargs):
        """
        Runs a print()-based report function on a background thread and pipes
        its output into a text box once done. Scans like Connections or Local
        Network can take a while (DNS lookups, pings, port checks) — running
        them on the main thread would freeze the whole window ("Not
        Responding") for the duration. Tkinter itself isn't thread-safe, so
        the worker thread only computes text; the actual widget update is
        scheduled back onto the main thread via root.after().
        """
        box.delete("1.0", tk.END)
        box.insert(tk.END, "Running...\n")

        def worker():
            buffer = io.StringIO()
            try:
                with contextlib.redirect_stdout(buffer):
                    func(*args, **kwargs)
            except Exception as e:
                buffer.write(f"\nError: {e}\n")
            output = buffer.getvalue()
            self.root.after(0, lambda: self._show_output(box, output))

        threading.Thread(target=worker, daemon=True).start()

    def _show_output(self, box, text):
        box.delete("1.0", tk.END)
        box.insert(tk.END, text)

    # ---------- Log Analyzer tab ----------
    def _build_log_tab(self, notebook):
        frame = ttk.Frame(notebook)

        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        self.log_path_var = tk.StringVar(value="sample_logs/auth.log")
        entry = ttk.Entry(top, textvariable=self.log_path_var, width=45)
        entry.pack(side="left", padx=(0, 6))

        ttk.Button(top, text="Browse...", command=self._browse_log_file).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Scan Log", command=self._scan_log).pack(side="left", padx=(0, 12))

        self.tail_button = ttk.Button(top, text="Start Live Tail", command=self._toggle_live_tail)
        self.tail_button.pack(side="left")

        self.tail_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.tail_status_var).pack(anchor="w", padx=10)

        self.log_output = self._make_output_box(frame)
        return frame

    def _browse_log_file(self):
        path = filedialog.askopenfilename(title="Select a log file")
        if path:
            self.log_path_var.set(path)

    def _scan_log(self):
        path = self.log_path_var.get()
        self.log_output.delete("1.0", tk.END)
        self.log_output.insert(tk.END, "Running...\n")

        def worker():
            buffer = io.StringIO()
            try:
                events = parse_log_file(path)
                if not events:
                    buffer.write("No parseable log events found. Check the file path/format.\n")
                else:
                    alerts = run_all_detectors(events)
                    if threat_intel.is_configured():
                        alerts += threat_intel.generate_threat_intel_alerts(events)
                    new_events = log_store.insert_events(events)
                    log_store.insert_alerts(alerts)
                    with contextlib.redirect_stdout(buffer):
                        log_main.print_report(events, alerts)
                    buffer.write(f"\n({new_events} new event(s) stored to the database for Search/Dashboard.)\n")
                    if not threat_intel.is_configured():
                        buffer.write("(No AbuseIPDB API key configured yet — see the Threat Intel tab.)\n")
            except FileNotFoundError:
                buffer.write(f"File not found: {path}\n")
            except Exception as e:
                buffer.write(f"Error: {e}\n")
            output = buffer.getvalue()
            self.root.after(0, lambda: self._show_output(self.log_output, output))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Live Tail (Log Analyzer tab) ----------
    def _toggle_live_tail(self):
        if self.tailer and self.tailer.is_running():
            self.tailer.stop()
            self.tailer = None
            self.tail_button.config(text="Start Live Tail")
            self.tail_status_var.set("Live tail stopped.")
            return

        path = self.log_path_var.get()
        self.log_output.delete("1.0", tk.END)
        self.log_output.insert(
            tk.END,
            f"Live-tailing {path} — watching for new lines appended to this file.\n"
            f"(This only reacts to NEW lines from now on; use Scan Log for existing history.)\n\n",
        )
        self.tailer = LogTailer(path, on_update=self._on_tail_update)
        self.tailer.start()
        self.tail_button.config(text="Stop Live Tail")
        self.tail_status_var.set(f"Live tailing: {path}")

    def _on_tail_update(self, new_events, new_alerts, error):
        """Called from the LogTailer's background thread — must hop to the main thread."""
        self.root.after(0, lambda: self._append_tail_update(new_events, new_alerts, error))

    def _append_tail_update(self, new_events, new_alerts, error):
        if error:
            self.log_output.insert(tk.END, f"\n[Live Tail error] {error}\n")
            self.log_output.see(tk.END)
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_output.insert(tk.END, f"[{timestamp}] +{len(new_events)} new event(s)\n")
        for a in new_alerts:
            self.log_output.insert(tk.END, f"    [{a.severity.upper()}] {a.rule}: {a.detail}\n")
        self.log_output.see(tk.END)

    def _on_close(self):
        if self.tailer:
            self.tailer.stop()
        if self.event_watcher:
            self.event_watcher.stop()
        self.root.destroy()

    # ---------- Connections tab ----------
    def _build_connections_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Button(top, text="Scan Active Connections", command=self._scan_connections).pack(side="left")
        self.conn_output = self._make_output_box(frame)
        return frame

    def _scan_connections(self):
        self._run_captured(self.conn_output, netwatch_connections.print_report)

    # ---------- Browser History tab ----------
    def _build_history_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        self.browser_var = tk.StringVar(value="chrome")
        ttk.Radiobutton(top, text="Chrome", variable=self.browser_var, value="chrome").pack(side="left", padx=(0, 6))
        ttk.Radiobutton(top, text="Edge", variable=self.browser_var, value="edge").pack(side="left", padx=(0, 12))
        ttk.Button(top, text="Load History", command=self._scan_history).pack(side="left")

        self.history_output = self._make_output_box(frame)
        return frame

    def _scan_history(self):
        self._run_captured(
            self.history_output,
            netwatch_browser_history.print_report,
            self.browser_var.get(),
            30,
        )

    # ---------- Local Network tab ----------
    def _build_network_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Button(top, text="Scan Local Network", command=self._scan_network).pack(side="left")
        self.network_output = self._make_output_box(frame)
        return frame

    def _scan_network(self):
        self._run_captured(self.network_output, netwatch_local_network.print_report)

    # ---------- Port Scan tab ----------
    def _build_portscan_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="Target IP (blank = scan whole network):").pack(side="left", padx=(0, 6))
        self.portscan_target_var = tk.StringVar(value="")
        entry = ttk.Entry(top, textvariable=self.portscan_target_var, width=16)
        entry.pack(side="left", padx=(0, 6))

        ttk.Button(top, text="Scan Ports", command=self._scan_ports).pack(side="left")

        self.portscan_output = self._make_output_box(frame)
        return frame

    def _scan_ports(self):
        target = self.portscan_target_var.get().strip() or None
        self._run_captured(self.portscan_output, netwatch_portscan.print_report, target)

    # ---------- PC Activity tab ----------
    def _build_pcactivity_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        self.pcactivity_button = ttk.Button(
            top, text="Start Monitoring", command=self._toggle_pcactivity)
        self.pcactivity_button.pack(side="left")

        self.pcactivity_status_var = tk.StringVar(value="")
        ttk.Label(frame, textvariable=self.pcactivity_status_var).pack(anchor="w", padx=10)

        self.pcactivity_output = self._make_output_box(frame)
        self.pcactivity_output.insert(
            tk.END,
            "Click 'Start Monitoring' to watch YOUR PC in real time:\n"
            "  - Logon events (Windows Security log — needs Administrator; "
            "run the app as admin to see these)\n"
            "  - New processes launching (flags anything running from Temp/Downloads, "
            "or disguised as a core Windows process)\n"
            "  - USB / removable drives connecting or disconnecting\n\n"
            "Only reacts to NEW activity from the moment you click Start — it won't "
            "flood you with everything already running.\n",
        )
        return frame

    def _toggle_pcactivity(self):
        if self.event_watcher and self.event_watcher.is_running():
            self.event_watcher.stop()
            self.event_watcher = None
            self.pcactivity_button.config(text="Start Monitoring")
            self.pcactivity_status_var.set("Monitoring stopped.")
            return

        self.pcactivity_output.delete("1.0", tk.END)
        self.pcactivity_output.insert(tk.END, "Starting monitor, checking Security log access...\n")
        self.pcactivity_button.config(text="Stop Monitoring")
        self.pcactivity_status_var.set("Monitoring...")

        self.event_watcher = EventWatcher(on_update=self._on_pcactivity_update)
        self.event_watcher.start()

        # Report logon-log availability once it's been checked (happens at
        # the top of the watcher's background loop, so poll briefly for it).
        self.root.after(1500, self._report_logon_availability)

    def _report_logon_availability(self):
        watcher = self.event_watcher
        if not watcher or watcher.logon_available is None:
            return  # still checking, or already stopped
        if watcher.logon_available:
            self.pcactivity_status_var.set("Monitoring... (Security log access OK — logon events included)")
        else:
            self.pcactivity_status_var.set(
                f"Monitoring... (Security log unavailable: {watcher.logon_unavailable_reason} "
                f"— process/USB monitoring still active)"
            )

    def _on_pcactivity_update(self, new_events, error):
        """Called from EventWatcher's background thread — must hop to the main thread."""
        self.root.after(0, lambda: self._append_pcactivity_update(new_events, error))

    def _append_pcactivity_update(self, new_events, error):
        if error:
            self.pcactivity_output.insert(tk.END, f"\n[PC Activity error] {error}\n")
            self.pcactivity_output.see(tk.END)
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        for e in new_events:
            self.pcactivity_output.insert(
                tk.END, f"[{timestamp}] [{e.risk.upper()}] ({e.category}) {e.detail}\n"
            )
        self.pcactivity_output.see(tk.END)

    # ---------- Threat Intel tab ----------
    def _build_threatintel_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="IP address:").pack(side="left")
        self.threatintel_ip_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.threatintel_ip_var, width=18).pack(side="left", padx=(4, 10))
        ttk.Button(top, text="Check IP", command=self._check_threat_intel).pack(side="left")

        self.threatintel_output = self._make_output_box(frame)

        if threat_intel.is_configured():
            intro = (
                "Look up any IP against AbuseIPDB — abuse confidence score, report "
                "count, country, and ISP.\n\nLog Analyzer scans and Live Tail already "
                "check failed-login IPs against this automatically and raise a "
                "'known_malicious_ip' alert for anything at or above "
                f"{threat_intel.HIGH_RISK_THRESHOLD}% confidence.\n"
            )
        else:
            intro = (
                "No AbuseIPDB API key configured yet, so threat intel checks are "
                "skipped everywhere in the app.\n\nTo enable it:\n"
                "  1. Sign up free at https://www.abuseipdb.com/register\n"
                "  2. Grab a key at https://www.abuseipdb.com/account/api\n"
                "  3. Paste it into config.py at the project root "
                "(ABUSEIPDB_API_KEY = \"your-key-here\")\n"
                "  4. Restart the app\n"
            )
        self.threatintel_output.insert(tk.END, intro)
        return frame

    def _check_threat_intel(self):
        ip = self.threatintel_ip_var.get().strip()
        if not ip:
            return

        if not threat_intel.is_configured():
            self.threatintel_output.delete("1.0", tk.END)
            self.threatintel_output.insert(
                tk.END,
                "No AbuseIPDB API key configured. Add one to config.py at the "
                "project root, then restart the app. See the Threat Intel tab's "
                "instructions above for the exact steps.\n",
            )
            return

        self.threatintel_output.delete("1.0", tk.END)
        self.threatintel_output.insert(tk.END, f"Checking {ip}...\n")

        def worker():
            buffer = io.StringIO()
            try:
                result = threat_intel.check_ip(ip, force_refresh=True)
                if result is None:
                    buffer.write(
                        f"No data for {ip} — it may be a private/local address "
                        f"(no public reputation data exists for those), or the "
                        f"lookup failed (check your API key / internet connection).\n"
                    )
                else:
                    buffer.write(f"IP: {result['ip']}\n")
                    buffer.write(f"Abuse confidence score: {result['abuse_score']}%\n")
                    buffer.write(f"Total reports: {result['total_reports']}\n")
                    buffer.write(f"Country: {result['country']}\n")
                    buffer.write(f"ISP: {result['isp']}\n")
                    buffer.write(f"Whitelisted: {result['is_whitelisted']}\n")
                    if result["abuse_score"] >= threat_intel.HIGH_RISK_THRESHOLD:
                        buffer.write(f"\n[!] This IP meets the high-risk threshold "
                                      f"({threat_intel.HIGH_RISK_THRESHOLD}%+) used for automatic alerts.\n")
            except Exception as e:
                buffer.write(f"Error: {e}\n")
            output = buffer.getvalue()
            self.root.after(0, lambda: self._show_output(self.threatintel_output, output))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Search tab ----------
    def _build_search_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)

        ttk.Label(top, text="IP:").pack(side="left")
        self.search_ip_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.search_ip_var, width=16).pack(side="left", padx=(2, 10))

        ttk.Label(top, text="Username:").pack(side="left")
        self.search_user_var = tk.StringVar(value="")
        ttk.Entry(top, textvariable=self.search_user_var, width=14).pack(side="left", padx=(2, 10))

        ttk.Label(top, text="Type:").pack(side="left")
        self.search_type_var = tk.StringVar(value="any")
        ttk.Combobox(
            top, textvariable=self.search_type_var, width=14, state="readonly",
            values=["any", "failed_login", "accepted_login"],
        ).pack(side="left", padx=(2, 10))

        ttk.Button(top, text="Search", command=self._run_search).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Clear Filters", command=self._clear_search_filters).pack(side="left")

        self.search_output = self._make_output_box(frame)
        return frame

    def _clear_search_filters(self):
        self.search_ip_var.set("")
        self.search_user_var.set("")
        self.search_type_var.set("any")

    def _run_search(self):
        ip = self.search_ip_var.get().strip() or None
        username = self.search_user_var.get().strip() or None
        event_type = self.search_type_var.get()
        event_type = None if event_type in ("", "any") else event_type

        self.search_output.delete("1.0", tk.END)
        self.search_output.insert(tk.END, "Searching...\n")

        def worker():
            buffer = io.StringIO()
            try:
                rows = log_store.query_events(ip=ip, username=username, event_type=event_type)
                if not rows:
                    buffer.write("No stored events match those filters.\n"
                                  "(Run a Log Analyzer scan or Live Tail first to populate the database.)\n")
                else:
                    buffer.write(f"{len(rows)} matching event(s) (most recent first, showing up to 500):\n\n")
                    for r in rows:
                        buffer.write(
                            f"  {r['timestamp']:<20} {r['event_type']:<16} "
                            f"user={r['username']:<12} ip={r['ip']:<16} port={r['port']}\n"
                        )
            except Exception as e:
                buffer.write(f"Error: {e}\n")
            output = buffer.getvalue()
            self.root.after(0, lambda: self._show_output(self.search_output, output))

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Dashboard tab ----------
    def _build_dashboard_tab(self, notebook):
        frame = ttk.Frame(notebook)
        top = ttk.Frame(frame)
        top.pack(fill="x", padx=10, pady=10)
        ttk.Button(top, text="Refresh Dashboard", command=self._refresh_dashboard).pack(side="left")

        self.dashboard_canvas_frame = ttk.Frame(frame)
        self.dashboard_canvas_frame.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        self.dashboard_canvas_widget = None

        placeholder = ttk.Label(
            self.dashboard_canvas_frame,
            text="Click 'Refresh Dashboard' to build charts from stored log data.",
        )
        placeholder.pack(pady=40)

        return frame

    def _refresh_dashboard(self):
        for child in self.dashboard_canvas_frame.winfo_children():
            child.destroy()
        ttk.Label(self.dashboard_canvas_frame, text="Building dashboard...").pack(pady=40)

        def worker():
            try:
                fig = dashboard.build_dashboard_figure()
                error = None
            except Exception as e:
                fig = None
                error = str(e)
            self.root.after(0, lambda: self._show_dashboard(fig, error))

        threading.Thread(target=worker, daemon=True).start()

    def _show_dashboard(self, fig, error):
        for child in self.dashboard_canvas_frame.winfo_children():
            child.destroy()

        if error or fig is None:
            ttk.Label(self.dashboard_canvas_frame, text=f"Error building dashboard: {error}").pack(pady=40)
            return

        canvas = FigureCanvasTkAgg(fig, master=self.dashboard_canvas_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)


def main():
    root = tk.Tk()
    app = CedarWatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
