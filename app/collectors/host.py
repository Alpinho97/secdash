"""Host health: failed services, kernel, reboot-required, time-sync, apparmor, journal volume."""
from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path
from typing import Any

_JOURNAL_PREV: dict[str, Any] = {"ts": 0.0, "bytes": 0}


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _failed_services() -> list[dict[str, str]]:
    rc, out = _run(["systemctl", "--failed", "--no-legend", "--plain", "--full"])
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 4:
            continue
        rows.append({
            "unit": parts[0],
            "load": parts[1],
            "active": parts[2],
            "sub": parts[3],
            "desc": parts[4] if len(parts) > 4 else "",
        })
    return rows


def _kernel() -> dict[str, Any]:
    rc, out = _run(["uname", "-r"])
    running = out.strip()
    # latest installed linux-image
    rc2, out2 = _run(["dpkg-query", "-W", "-f=${Package}\\n", "linux-image-*"])
    latest = ""
    versions: list[str] = []
    for line in out2.splitlines():
        pkg = line.strip()
        # match e.g. linux-image-6.8.0-111-generic (skip meta-packages like linux-image-generic)
        suffix = pkg.replace("linux-image-", "")
        if not suffix or suffix in ("generic", "virtual"):
            continue
        if suffix[0].isdigit():
            versions.append(suffix)
    # Sort by tuple of version components so 6.8.0-111 > 6.8.0-99
    def _vkey(v: str) -> tuple:
        import re
        return tuple(int(x) if x.isdigit() else x for x in re.split(r"[.-]", v))
    versions.sort(key=_vkey)
    if versions:
        latest = versions[-1]
    reboot_required = Path("/var/run/reboot-required").is_file()
    pkgs_path = Path("/var/run/reboot-required.pkgs")
    reboot_pkgs: list[str] = []
    if pkgs_path.is_file():
        try:
            reboot_pkgs = [l.strip() for l in pkgs_path.read_text().splitlines() if l.strip()]
        except OSError:
            pass
    return {
        "running": running,
        "latest_installed": latest,
        "needs_reboot": reboot_required,
        "outdated": bool(latest and running and latest != running),
        "reboot_pkgs": reboot_pkgs,
    }


def _time_sync() -> dict[str, Any]:
    rc, out = _run(["timedatectl", "show"])
    if rc != 0:
        return {"available": False}
    kv: dict[str, str] = {}
    for line in out.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            kv[k.strip()] = v.strip()
    return {
        "available": True,
        "ntp": kv.get("NTP", ""),
        "ntp_synchronized": kv.get("NTPSynchronized", "") == "yes",
        "timezone": kv.get("Timezone", ""),
        "local_time": kv.get("TimeUSec", ""),
    }


def _apparmor() -> dict[str, Any]:
    rc, out = _run(["aa-status", "--json"], timeout=10)
    if rc == 0 and out.strip():
        try:
            import json
            d = json.loads(out)
            profiles = d.get("profiles", {})
            return {
                "available": True,
                "enforce": profiles.get("enforce", 0),
                "complain": profiles.get("complain", 0),
                "kill": profiles.get("kill", 0),
                "unconfined": profiles.get("unconfined", 0),
            }
        except Exception:
            pass
    # Fallback: numeric-only
    rc, out = _run(["aa-status"])
    if rc != 0:
        return {"available": False}
    return {"available": True, "raw": out[:500]}


def _journal_size() -> dict[str, Any]:
    """Total disk usage of journald + rough rate."""
    rc, out = _run(["journalctl", "--disk-usage"], timeout=5)
    size = ""
    bytes_total = 0
    if rc == 0:
        # "Archived and active journals take up 1.2G in the file system."
        size = out.strip()
        import re
        m = re.search(r"([\d.]+)([KMG])", size)
        if m:
            v = float(m.group(1))
            mul = {"K": 1024, "M": 1024**2, "G": 1024**3}[m.group(2)]
            bytes_total = int(v * mul)

    now = time.time()
    prev_ts = _JOURNAL_PREV["ts"]
    prev_bytes = _JOURNAL_PREV["bytes"]
    rate = 0.0
    if prev_ts and bytes_total >= prev_bytes:
        dt = now - prev_ts
        if dt > 0:
            rate = (bytes_total - prev_bytes) / dt
    _JOURNAL_PREV["ts"] = now
    _JOURNAL_PREV["bytes"] = bytes_total
    return {"size_text": size, "bytes_total": bytes_total, "bytes_per_sec": rate}


def collect() -> dict[str, Any]:
    failed = _failed_services()
    return {
        "failed_services": failed,
        "failed_count": len(failed),
        "kernel": _kernel(),
        "time": _time_sync(),
        "apparmor": _apparmor(),
        "journal": _journal_size(),
    }
