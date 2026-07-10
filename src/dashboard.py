"""
dashboard.py
Builds a matplotlib Figure summarizing everything stored in log_store:
top offending IPs, failed logins over time, and alert severity breakdown.
This is the "looks like a SIEM dashboard" piece — a glance at trends instead
of scrolling through a text report.

The Figure is built via matplotlib.figure.Figure directly rather than
pyplot.subplots() — pyplot's subplots() creates a full interactive figure
manager (window, toolbar, event hooks) tied to whichever thread calls it.
Since gui.py builds this figure on a background thread (to avoid freezing
the window), that would create Tkinter objects outside the main thread and
crash with "main thread is not in main loop" the moment the toolbar tried to
react to a mouse move. Figure() has none of that baggage — it's just a plain
drawing surface, safe to build on any thread. The actual Tk embedding
(FigureCanvasTkAgg) still happens on the main thread, in gui.py.

Running this file directly saves the figure to dashboard_preview.png, for a
quick look outside the GUI.

Usage:
    python src/dashboard.py
"""

from matplotlib.figure import Figure

import log_store

# Colors pulled from the GUI's existing dark-green theme, so the embedded
# charts don't look like a mismatched widget bolted onto the app.
BG = "#1e2a1e"
PANEL_BG = "#0f170f"
FG = "#c8e6c8"
ACCENT = "#4caf6b"
SEVERITY_COLORS = {"high": "#e05555", "medium": "#e0b955", "low": "#5599e0"}


def build_dashboard_figure():
    summary = log_store.total_counts()
    top = log_store.top_ips(limit=8)
    hourly = log_store.events_per_hour()
    severity = log_store.alert_severity_counts()

    fig = Figure(figsize=(13, 4.2))
    axes = fig.subplots(1, 3)
    fig.patch.set_facecolor(BG)
    fig.suptitle(
        f"Cedar Watch — {summary['events']} events | {summary['alerts']} alerts | "
        f"{summary['distinct_ips']} distinct IPs",
        color=FG, fontsize=11,
    )

    # ---- Panel 1: Top offending IPs ----
    ax = axes[0]
    _style_axis(ax)
    ax.set_title("Top Offending IPs (failed logins)", color=FG, fontsize=10)
    if top:
        ips, counts = zip(*top)
        ax.barh(range(len(ips)), counts, color=ACCENT)
        ax.set_yticks(range(len(ips)))
        ax.set_yticklabels(ips, color=FG, fontsize=8)
        ax.invert_yaxis()
        ax.set_xlabel("failed attempts", color=FG, fontsize=8)
    else:
        _empty_panel(ax, "No failed logins recorded yet")

    # ---- Panel 2: Failed logins over time ----
    ax = axes[1]
    _style_axis(ax)
    ax.set_title("Failed Logins Over Time", color=FG, fontsize=10)
    if hourly:
        buckets, counts = zip(*hourly)
        ax.plot(range(len(buckets)), counts, color=ACCENT, marker="o", markersize=3)
        ax.fill_between(range(len(buckets)), counts, color=ACCENT, alpha=0.2)
        step = max(1, len(buckets) // 6)
        ax.set_xticks(range(0, len(buckets), step))
        ax.set_xticklabels([buckets[i] for i in range(0, len(buckets), step)],
                            color=FG, fontsize=7, rotation=45, ha="right")
        ax.set_ylabel("failed logins / hour", color=FG, fontsize=8)
    else:
        _empty_panel(ax, "No time-series data yet")

    # ---- Panel 3: Alert severity breakdown ----
    ax = axes[2]
    _style_axis(ax)
    ax.set_title("Alerts by Severity", color=FG, fontsize=10)
    if severity:
        labels = list(severity.keys())
        values = [severity[k] for k in labels]
        colors = [SEVERITY_COLORS.get(k, ACCENT) for k in labels]
        ax.bar(labels, values, color=colors)
        ax.set_ylabel("alert count", color=FG, fontsize=8)
        ax.tick_params(colors=FG, labelsize=8)
    else:
        _empty_panel(ax, "No alerts recorded yet")

    fig.tight_layout(rect=[0, 0, 1, 0.93])
    return fig


def _style_axis(ax):
    ax.set_facecolor(PANEL_BG)
    ax.tick_params(colors=FG, labelsize=8)
    for spine in ax.spines.values():
        spine.set_color(FG)


def _empty_panel(ax, message):
    ax.text(0.5, 0.5, message, ha="center", va="center", color=FG, fontsize=9, transform=ax.transAxes)
    ax.set_xticks([])
    ax.set_yticks([])


if __name__ == "__main__":
    fig = build_dashboard_figure()
    out_path = "dashboard_preview.png"
    fig.savefig(out_path, facecolor=fig.get_facecolor())
    print(f"Saved dashboard preview to {out_path}")
