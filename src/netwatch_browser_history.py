"""
browser_history.py
Reads your recent browser history (Chrome or Edge, both use the same SQLite
format) so you can see what sites you've visited.

Chrome/Edge lock their History database while running, so this copies it to a
temp file first, then queries the copy — this is the standard workaround.

Usage:
    python src/netwatch_browser_history.py            # auto-detect Chrome/Edge
    python src/netwatch_browser_history.py --browser edge
    python src/netwatch_browser_history.py --limit 50
"""

import os
import sys
import sqlite3
import shutil
import tempfile
import argparse
import platform
from datetime import datetime, timedelta


def get_history_path(browser="chrome"):
    """
    Returns the default History file path for the given browser, based on OS.
    Covers Windows, macOS, and Linux default profile locations.
    """
    system = platform.system()
    home = os.path.expanduser("~")

    paths = {
        ("Windows", "chrome"): rf"{home}\AppData\Local\Google\Chrome\User Data\Default\History",
        ("Windows", "edge"): rf"{home}\AppData\Local\Microsoft\Edge\User Data\Default\History",
        ("Darwin", "chrome"): f"{home}/Library/Application Support/Google/Chrome/Default/History",
        ("Darwin", "edge"): f"{home}/Library/Application Support/Microsoft Edge/Default/History",
        ("Linux", "chrome"): f"{home}/.config/google-chrome/Default/History",
        ("Linux", "edge"): f"{home}/.config/microsoft-edge/Default/History",
    }

    return paths.get((system, browser))


def chrome_timestamp_to_datetime(chrome_time):
    """Chrome stores timestamps as microseconds since 1601-01-01 (Windows epoch)."""
    if not chrome_time:
        return None
    epoch_start = datetime(1601, 1, 1)
    return epoch_start + timedelta(microseconds=chrome_time)


def read_history(browser="chrome", limit=50):
    """Returns a list of (url, title, visit_time, visit_count) tuples, most recent first."""
    history_path = get_history_path(browser)

    if not history_path or not os.path.exists(history_path):
        print(f"Couldn't find {browser} history at expected path: {history_path}")
        print("Make sure the browser is installed and has been used at least once.")
        return []

    # Copy to a temp file since the browser locks the original while running
    tmp_copy = os.path.join(tempfile.gettempdir(), f"cedarwatch_{browser}_history_copy")
    shutil.copy2(history_path, tmp_copy)

    conn = sqlite3.connect(tmp_copy)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT url, title, last_visit_time, visit_count
        FROM urls
        ORDER BY last_visit_time DESC
        LIMIT ?
    """, (limit,))

    rows = cursor.fetchall()
    conn.close()
    os.remove(tmp_copy)

    results = []
    for url, title, chrome_time, visit_count in rows:
        visit_dt = chrome_timestamp_to_datetime(chrome_time)
        results.append({
            "url": url,
            "title": title,
            "visited_at": visit_dt,
            "visit_count": visit_count,
        })
    return results


def print_report(browser="chrome", limit=50):
    print("=" * 70)
    print(f"  BROWSER HISTORY — {browser.upper()} (last {limit} sites)")
    print("=" * 70)

    entries = read_history(browser, limit)

    if not entries:
        return

    for e in entries:
        ts = e["visited_at"].strftime("%Y-%m-%d %H:%M") if e["visited_at"] else "unknown time"
        title = (e["title"][:50] + "...") if e["title"] and len(e["title"]) > 50 else (e["title"] or "")
        print(f"  [{ts}] {title}")
        print(f"      {e['url']}")

    print("\n" + "=" * 70)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Read your recent browser history.")
    parser.add_argument("--browser", choices=["chrome", "edge"], default="chrome",
                         help="Which browser to read history from (default: chrome)")
    parser.add_argument("--limit", type=int, default=50, help="Number of recent entries to show")
    args = parser.parse_args()

    print_report(args.browser, args.limit)
