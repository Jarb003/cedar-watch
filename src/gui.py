"""
gui.py
Simple desktop UI for Cedar Watch. Tabs for:
  - Log Analyzer (scan an SSH auth log file)
  - Connections (who your laptop is talking to)
  - Browser History (recent sites visited)
  - Local Network (devices on your WiFi/LAN)
  - Port Scan (blue-team check for risky open ports on your LAN)

Uses only the Python standard library for the UI itself (tkinter).

Usage:
    python src/gui.py
"""

import io
import contextlib
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext

import netwatch_connections
import netwatch_browser_history
import netwatch_local_network
import netwatch_portscan
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

        notebook = ttk.Notebook(root)
        notebook.pack(fill="both", expand=True, padx=8, pady=8)

        self.log_tab = self._build_log_tab(notebook)
        self.conn_tab = self._build_connections_tab(notebook)
        self.history_tab = self._build_history_tab(notebook)
        self.network_tab = self._build_network_tab(notebook)
        self.portscan_tab = self._build_portscan_tab(notebook)

        notebook.add(self.log_tab, text="Log Analyzer")
        notebook.add(self.conn_tab, text="Connections")
        notebook.add(self.history_tab, text="Browser History")
        notebook.add(self.network_tab, text="Local Network")
        notebook.add(self.portscan_tab, text="Port Scan")

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
        entry = ttk.Entry(top, textvariable=self.log_path_var, width=60)
        entry.pack(side="left", padx=(0, 6))

        ttk.Button(top, text="Browse...", command=self._browse_log_file).pack(side="left", padx=(0, 6))
        ttk.Button(top, text="Scan Log", command=self._scan_log).pack(side="left")

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
                    with contextlib.redirect_stdout(buffer):
                        log_main.print_report(events, alerts)
            except FileNotFoundError:
                buffer.write(f"File not found: {path}\n")
            except Exception as e:
                buffer.write(f"Error: {e}\n")
            output = buffer.getvalue()
            self.root.after(0, lambda: self._show_output(self.log_output, output))

        threading.Thread(target=worker, daemon=True).start()

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


def main():
    root = tk.Tk()
    app = CedarWatchApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
