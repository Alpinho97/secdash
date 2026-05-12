"""Active + recent login sessions and sudo audit."""
from __future__ import annotations

import re
import subprocess
from collections import Counter
from typing import Any


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _who() -> list[dict[str, str]]:
    """`who -u` — currently logged-in sessions."""
    rc, out = _run(["who", "-uH"])
    rows: list[dict[str, str]] = []
    for i, line in enumerate(out.splitlines()):
        if i == 0 or not line.strip():
            continue
        parts = line.split()
        # NAME LINE TIME IDLE PID COMMENT
        if len(parts) < 5:
            continue
        rows.append({
            "user": parts[0],
            "tty": parts[1],
            "login": " ".join(parts[2:4]),
            "idle": parts[4] if len(parts) > 4 else "",
            "pid": parts[5] if len(parts) > 5 else "",
            "from": parts[-1].strip("()") if parts[-1].startswith("(") else "",
        })
    return rows


def _last(n: int = 30) -> list[dict[str, str]]:
    """`last -F -n N` — recent successful logins."""
    rc, out = _run(["last", "-F", "-n", str(n), "-w"])
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        if not line.strip() or line.startswith("wtmp"):
            continue
        parts = line.split()
        if len(parts) < 4:
            continue
        rows.append({
            "user": parts[0],
            "tty": parts[1],
            "from": parts[2] if len(parts) > 2 else "",
            "raw": line.rstrip(),
        })
    return rows


def _lastb(n: int = 30) -> list[str]:
    """`lastb` — failed logins (btmp). Requires root."""
    rc, out = _run(["lastb", "-F", "-n", str(n), "-w"])
    if rc != 0:
        return []
    return [l.rstrip() for l in out.splitlines() if l.strip() and not l.startswith("btmp")]


# sudo log lines:
#   sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
#   sudo: pam_unix(sudo:auth): authentication failure; logname=alice …
RE_SUDO_OK = re.compile(
    r"sudo:\s*(?P<user>\S+)\s*:\s*TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>\S+)\s*;\s*USER=(?P<asuser>\S+)\s*;\s*COMMAND=(?P<cmd>.+)$"
)
RE_SUDO_FAIL = re.compile(r"sudo:.*authentication failure.*logname=(?P<user>\S+)")


def _sudo_audit() -> dict[str, Any]:
    """Pull last 24h of sudo activity from journal."""
    rc, out = _run([
        "journalctl", "_COMM=sudo", "--since", "24 hours ago",
        "-o", "short-iso", "--no-pager",
    ], timeout=15)
    ok: list[dict[str, str]] = []
    fails: list[dict[str, str]] = []
    if rc != 0:
        # fallback to auth.log
        try:
            with open("/var/log/auth.log") as fh:
                lines = fh.readlines()[-5000:]
            out = "".join(l for l in lines if "sudo" in l)
        except (OSError, PermissionError):
            out = ""
    for line in out.splitlines():
        m = RE_SUDO_OK.search(line)
        if m:
            ts = line.split(" ", 1)[0] if " " in line else ""
            ok.append({
                "ts": ts, "user": m["user"], "tty": m["tty"],
                "as": m["asuser"], "cmd": m["cmd"],
            })
            continue
        m = RE_SUDO_FAIL.search(line)
        if m:
            ts = line.split(" ", 1)[0] if " " in line else ""
            fails.append({"ts": ts, "user": m["user"], "line": line.rstrip()})
    top_users = Counter(e["user"] for e in ok).most_common(10)
    return {
        "ok_count": len(ok),
        "fail_count": len(fails),
        "recent_ok": ok[-40:][::-1],
        "recent_fails": fails[-20:][::-1],
        "top_users": top_users,
    }


def collect() -> dict[str, Any]:
    who = _who()
    return {
        "active": who,
        "active_count": len(who),
        "recent_logins": _last(30),
        "recent_failed_logins": _lastb(30),
        "sudo": _sudo_audit(),
    }
