"""Top processes by CPU% and RSS.

Pure /proc reader — no psutil.
"""
from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

# Cache /proc/<pid>/stat[cpu_jiffies] across calls so we can compute deltas.
_PREV: dict[str, Any] = {"ts": 0.0, "pid_jiffies": {}}

_CLK_TCK = os.sysconf("SC_CLK_TCK") or 100
_PAGE_SIZE = os.sysconf("SC_PAGE_SIZE") or 4096


def _read_uptime() -> float:
    try:
        with open("/proc/uptime") as fh:
            return float(fh.readline().split()[0])
    except (OSError, ValueError):
        return 0.0


def _read_stat(pid: str) -> dict[str, Any] | None:
    try:
        with open(f"/proc/{pid}/stat", "rb") as fh:
            raw = fh.read().decode(errors="replace")
    except (OSError, PermissionError):
        return None
    # comm is in parens and may contain spaces/parens — locate the LAST ')'.
    rpar = raw.rfind(")")
    if rpar == -1:
        return None
    lpar = raw.find("(")
    comm = raw[lpar + 1: rpar]
    rest = raw[rpar + 2:].split()
    # Fields after comm: state(0) ppid(1) pgrp uid... utime(11), stime(12), rss(21) … (man proc)
    try:
        utime = int(rest[11])
        stime = int(rest[12])
        starttime = int(rest[19])
        rss_pages = int(rest[21])
    except (IndexError, ValueError):
        return None
    return {"pid": pid, "comm": comm, "utime": utime, "stime": stime, "starttime": starttime, "rss": rss_pages * _PAGE_SIZE}


def _read_status(pid: str) -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        with open(f"/proc/{pid}/status") as fh:
            for line in fh:
                k, _, v = line.partition(":")
                out[k.strip()] = v.strip()
    except (OSError, PermissionError):
        pass
    return out


def _cmdline(pid: str) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read().replace(b"\x00", b" ").strip()
        return raw.decode(errors="replace")
    except (OSError, PermissionError):
        return ""


def collect(top_n: int = 20) -> dict[str, Any]:
    now = time.time()
    pids = [p.name for p in Path("/proc").iterdir() if p.name.isdigit()]
    cur_stats: dict[str, dict[str, Any]] = {}
    procs: list[dict[str, Any]] = []
    prev_map = _PREV["pid_jiffies"]
    prev_ts = _PREV["ts"]
    dt = max(now - prev_ts, 0.001) if prev_ts else 0
    ncpu = os.cpu_count() or 1

    for pid in pids:
        st = _read_stat(pid)
        if not st:
            continue
        cur_jiffies = st["utime"] + st["stime"]
        cur_stats[pid] = {"jiffies": cur_jiffies, "starttime": st["starttime"]}
        cpu_pct = 0.0
        if dt and pid in prev_map and prev_map[pid]["starttime"] == st["starttime"]:
            delta = cur_jiffies - prev_map[pid]["jiffies"]
            cpu_pct = (delta / _CLK_TCK) / dt * 100
            cpu_pct = max(cpu_pct, 0)
        status = _read_status(pid)
        user = status.get("Uid", "0").split()[0] if status.get("Uid") else "0"
        procs.append({
            "pid": pid,
            "comm": st["comm"],
            "uid": user,
            "cpu_pct": round(cpu_pct, 1),
            "rss": st["rss"],
            "cmdline": _cmdline(pid),
        })

    _PREV["ts"] = now
    _PREV["pid_jiffies"] = cur_stats

    by_cpu = sorted(procs, key=lambda p: -p["cpu_pct"])[:top_n]
    by_rss = sorted(procs, key=lambda p: -p["rss"])[:top_n]
    return {"top_cpu": by_cpu, "top_rss": by_rss, "total": len(procs), "ncpu": ncpu}
