"""Pending updates + CVE collector. Caches results for 1h because debsecan is slow."""
from __future__ import annotations

import re
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

_CACHE: dict[str, Any] = {"ts": 0.0, "data": None}
_TTL = 3600  # 1 hour

# `apt list --upgradable` line:
# pkg/noble-security,noble-security 1.2.3 amd64 [upgradable from: 1.2.2]
RE_APT_LINE = re.compile(r"^(?P<pkg>[^/]+)/(?P<pocket>\S+)\s+(?P<newver>\S+)\s+(?P<arch>\S+)")

# debsecan --format detail lines like:
# CVE-2024-1234 high urgency (remote) bookworm: openssl
RE_DEBSECAN = re.compile(
    r"^(?P<cve>CVE-\d{4}-\d+)\s+(?:(?P<urgency>\S+)\s+urgency\s+)?(?:\((?P<flags>[^)]+)\)\s+)?(?P<suite>\S+):\s+(?P<pkg>\S+)"
)


def _run(argv: list[str], timeout: int = 60) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _apt_upgradable() -> list[dict[str, Any]]:
    rc, out = _run(["apt", "list", "--upgradable"], timeout=30)
    rows: list[dict[str, Any]] = []
    for line in out.splitlines():
        m = RE_APT_LINE.match(line)
        if not m:
            continue
        is_sec = "security" in m["pocket"].lower()
        rows.append({
            "pkg": m["pkg"],
            "pocket": m["pocket"],
            "new_version": m["newver"],
            "arch": m["arch"],
            "is_security": is_sec,
        })
    return rows


def _debsecan() -> dict[str, Any]:
    rc, out = _run(["debsecan", "--suite", "noble", "--format", "detail"], timeout=120)
    if rc != 0 or not out.strip():
        return {"available": False, "by_pkg": {}, "total": 0, "remote_count": 0}
    by_pkg: dict[str, list[dict[str, str]]] = defaultdict(list)
    remote = 0
    total = 0
    for line in out.splitlines():
        m = RE_DEBSECAN.match(line.strip())
        if not m:
            continue
        total += 1
        flags = m.group("flags") or ""
        is_remote = "remote" in flags
        if is_remote:
            remote += 1
        by_pkg[m["pkg"]].append({
            "cve": m["cve"],
            "urgency": m.group("urgency") or "",
            "flags": flags,
            "remote": is_remote,
        })
    return {"available": True, "by_pkg": dict(by_pkg), "total": total, "remote_count": remote}


def _unattended_tail(n: int = 40) -> list[str]:
    path = Path("/var/log/unattended-upgrades/unattended-upgrades.log")
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return fh.readlines()[-n:]
    except (PermissionError, OSError):
        return []


def collect(force: bool = False) -> dict[str, Any]:
    now = time.time()
    if not force and _CACHE["data"] is not None and (now - _CACHE["ts"] < _TTL):
        cached = dict(_CACHE["data"])
        cached["cached"] = True
        cached["age_seconds"] = int(now - _CACHE["ts"])
        return cached

    upgradable = _apt_upgradable()
    cve = _debsecan()
    log_tail = _unattended_tail()

    data = {
        "upgradable": upgradable,
        "upgradable_total": len(upgradable),
        "upgradable_security": sum(1 for u in upgradable if u["is_security"]),
        "cve": cve,
        "unattended_tail": [l.rstrip() for l in log_tail],
        "cached": False,
        "age_seconds": 0,
    }
    _CACHE["data"] = data
    _CACHE["ts"] = now
    return data
