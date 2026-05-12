"""Realtime system-resource collector.

CPU%, memory, swap, load average, uptime, and per-mount disk usage.
Stdlib only (no psutil) — reads /proc and uses shutil.disk_usage.
"""
from __future__ import annotations

import os
import shutil
import time
from pathlib import Path
from typing import Any

# Filesystem types we don't want to report on (pseudo / virtual / overlay).
_SKIP_FSTYPES = {
    "proc", "sysfs", "devtmpfs", "devpts", "tmpfs", "cgroup", "cgroup2",
    "pstore", "bpf", "tracefs", "debugfs", "securityfs", "configfs",
    "fusectl", "mqueue", "hugetlbfs", "autofs", "binfmt_misc", "rpc_pipefs",
    "nsfs", "ramfs", "fuse.gvfsd-fuse", "fuse.portal", "squashfs",
    "overlay", "fuse.snapfuse",
}

# Don't recurse into these mount-point prefixes; they bloat the list.
_SKIP_PREFIXES = (
    "/snap/", "/var/lib/docker/", "/run/", "/sys/", "/proc/", "/dev/",
    "/var/lib/snapd/", "/var/lib/containerd/",
)


# ---- CPU ----

def _read_cpu_jiffies() -> tuple[int, int]:
    """Return (idle_jiffies, total_jiffies) from /proc/stat."""
    with open("/proc/stat", "rb") as fh:
        line = fh.readline().decode()
    # cpu  user nice system idle iowait irq softirq steal guest guest_nice
    parts = [int(x) for x in line.split()[1:]]
    idle = parts[3] + (parts[4] if len(parts) > 4 else 0)  # idle + iowait
    total = sum(parts)
    return idle, total


def _cpu_percent(sample_seconds: float = 0.25) -> float:
    """Sample /proc/stat twice and compute % busy."""
    idle1, total1 = _read_cpu_jiffies()
    time.sleep(sample_seconds)
    idle2, total2 = _read_cpu_jiffies()
    dt = max(total2 - total1, 1)
    di = idle2 - idle1
    return round((1.0 - di / dt) * 100, 1)


# ---- Memory ----

def _read_meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    with open("/proc/meminfo", "r") as fh:
        for line in fh:
            key, _, rest = line.partition(":")
            value = rest.strip().split()
            if not value:
                continue
            try:
                kb = int(value[0])
            except ValueError:
                continue
            out[key.strip()] = kb * 1024  # bytes
    return out


def _mem() -> dict[str, Any]:
    m = _read_meminfo()
    total = m.get("MemTotal", 0)
    avail = m.get("MemAvailable", m.get("MemFree", 0))
    used = max(total - avail, 0)
    swap_total = m.get("SwapTotal", 0)
    swap_free = m.get("SwapFree", 0)
    swap_used = max(swap_total - swap_free, 0)
    return {
        "total": total,
        "available": avail,
        "used": used,
        "percent": round((used / total) * 100, 1) if total else 0.0,
        "buffers": m.get("Buffers", 0),
        "cached": m.get("Cached", 0),
        "swap_total": swap_total,
        "swap_used": swap_used,
        "swap_percent": round((swap_used / swap_total) * 100, 1) if swap_total else 0.0,
    }


# ---- Disks ----

def _mounts() -> list[tuple[str, str, str]]:
    """Return [(device, mountpoint, fstype)] from /proc/mounts."""
    rows: list[tuple[str, str, str]] = []
    try:
        with open("/proc/mounts", "r") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 3:
                    continue
                rows.append((parts[0], parts[1], parts[2]))
    except OSError:
        pass
    return rows


def _disks() -> list[dict[str, Any]]:
    seen: set[tuple[int, int]] = set()  # dedupe by device id (bind mounts)
    out: list[dict[str, Any]] = []
    for dev, mnt, fstype in _mounts():
        if fstype in _SKIP_FSTYPES:
            continue
        if any(mnt.startswith(p) for p in _SKIP_PREFIXES) and mnt != "/":
            continue
        try:
            st = os.stat(mnt)
        except OSError:
            continue
        key = (st.st_dev, 0)
        if key in seen:
            continue
        seen.add(key)
        try:
            usage = shutil.disk_usage(mnt)
        except (OSError, PermissionError):
            continue
        out.append({
            "device": dev,
            "mount": mnt,
            "fstype": fstype,
            "total": usage.total,
            "used": usage.used,
            "free": usage.free,
            "percent": round((usage.used / usage.total) * 100, 1) if usage.total else 0.0,
        })
    out.sort(key=lambda r: r["mount"])
    return out


# ---- Load / uptime ----

def _load() -> dict[str, float]:
    try:
        l1, l5, l15 = os.getloadavg()
    except OSError:
        l1 = l5 = l15 = 0.0
    return {"1m": round(l1, 2), "5m": round(l5, 2), "15m": round(l15, 2)}


def _uptime_seconds() -> float:
    try:
        with open("/proc/uptime", "r") as fh:
            return float(fh.readline().split()[0])
    except (OSError, ValueError):
        return 0.0


def _cpu_count() -> int:
    return os.cpu_count() or 1


# ---- Public API ----

def collect(sample_seconds: float = 0.25) -> dict[str, Any]:
    return {
        "cpu_percent": _cpu_percent(sample_seconds),
        "cpu_count": _cpu_count(),
        "load": _load(),
        "memory": _mem(),
        "disks": _disks(),
        "uptime_seconds": _uptime_seconds(),
        "timestamp": time.time(),
    }
