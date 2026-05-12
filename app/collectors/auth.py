"""SSH auth log collector.

Reads recent sshd events from journalctl (preferred) or /var/log/auth.log (fallback)
and aggregates failed/successful logins by IP and target user.
"""
from __future__ import annotations

import json
import re
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any

# Patterns are matched against the message body of each sshd log line.
RE_FAILED = re.compile(
    r"Failed (?P<method>password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
RE_DISCONNECT_PREAUTH = re.compile(
    r"Disconnected from (?:authenticating |invalid )?user (?P<user>\S+) (?P<ip>\S+) port \d+ \[preauth\]"
)


def _read_journal(since: str = "24 hours ago") -> list[dict[str, Any]]:
    """Read sshd entries from journalctl as JSON lines. Empty list on failure."""
    try:
        proc = subprocess.run(
            [
                "journalctl",
                "-u", "ssh.service",
                "-u", "ssh",
                "-u", "sshd",
                "--since", since,
                "-o", "json",
                "--no-pager",
            ],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    rows: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _iter_authlog_lines() -> list[tuple[str, str]]:
    """Fallback: read /var/log/auth.log directly. Returns [(timestamp, message)]."""
    path = Path("/var/log/auth.log")
    if not path.is_file():
        return []
    out: list[tuple[str, str]] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if "sshd" not in line:
                    continue
                # Format: "May 12 19:47:01 host sshd[1234]: message"
                parts = line.split(" ", 5)
                if len(parts) < 6:
                    continue
                ts = " ".join(parts[:3])
                msg = parts[5].strip()
                out.append((ts, msg))
    except PermissionError:
        return []
    return out[-5000:]


def _classify(msg: str) -> dict[str, str] | None:
    m = RE_FAILED.search(msg)
    if m:
        return {"kind": "failed", "user": m["user"], "ip": m["ip"], "method": m["method"]}
    m = RE_ACCEPTED.search(msg)
    if m:
        return {"kind": "accepted", "user": m["user"], "ip": m["ip"], "method": m["method"]}
    m = RE_INVALID.search(msg)
    if m:
        return {"kind": "invalid", "user": m["user"], "ip": m["ip"], "method": "n/a"}
    return None


def collect() -> dict[str, Any]:
    journal_rows = _read_journal()
    events: list[dict[str, Any]] = []
    if journal_rows:
        for r in journal_rows:
            msg = r.get("MESSAGE", "")
            if not isinstance(msg, str):
                continue
            cl = _classify(msg)
            if not cl:
                continue
            ts_us = r.get("__REALTIME_TIMESTAMP")
            try:
                ts = datetime.fromtimestamp(int(ts_us) / 1_000_000).isoformat(timespec="seconds")
            except (TypeError, ValueError):
                ts = ""
            cl["ts"] = ts
            events.append(cl)
    else:
        for ts, msg in _iter_authlog_lines():
            cl = _classify(msg)
            if cl:
                cl["ts"] = ts
                events.append(cl)

    failed = [e for e in events if e["kind"] in ("failed", "invalid")]
    accepted = [e for e in events if e["kind"] == "accepted"]

    top_ips = Counter(e["ip"] for e in failed).most_common(15)
    top_users = Counter(e["user"] for e in failed).most_common(15)

    return {
        "total_events": len(events),
        "failed_count": len(failed),
        "accepted_count": len(accepted),
        "top_ips": top_ips,
        "top_users": top_users,
        "recent_failed": failed[-50:][::-1],
        "recent_accepted": accepted[-20:][::-1],
        "source": "journalctl" if journal_rows else "auth.log",
    }
