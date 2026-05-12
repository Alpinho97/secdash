"""Cron jobs, systemd timers, SUID/SGID inventory.

Persistence mechanisms are classic attacker hiding-spots.
"""
from __future__ import annotations

import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Any

# SUID scan is slow (~5s); cache for 10 minutes.
_SUID_CACHE: dict[str, Any] = {"ts": 0.0, "rows": []}
_SUID_TTL = 600


def _run(argv: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _system_cron() -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    # /etc/crontab and /etc/cron.d/*
    paths = [Path("/etc/crontab")]
    cron_d = Path("/etc/cron.d")
    if cron_d.is_dir():
        try:
            paths.extend(p for p in cron_d.iterdir() if p.is_file())
        except OSError:
            pass
    for p in paths:
        try:
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                s = line.strip()
                if not s or s.startswith("#") or s.startswith("SHELL=") or s.startswith("PATH=") or "=" in s.split()[0] if s else False:
                    continue
                rows.append({"file": str(p), "line": s})
        except (OSError, PermissionError):
            continue
    # cron.{hourly,daily,weekly,monthly} — just enumerate scripts
    for sub in ("cron.hourly", "cron.daily", "cron.weekly", "cron.monthly"):
        d = Path("/etc") / sub
        if not d.is_dir():
            continue
        try:
            for p in d.iterdir():
                if p.is_file():
                    rows.append({"file": str(d), "line": f"@{sub}: {p.name}"})
        except OSError:
            pass
    return rows


def _user_cron() -> list[dict[str, str]]:
    """/var/spool/cron/crontabs/<user>"""
    rows: list[dict[str, str]] = []
    spool = Path("/var/spool/cron/crontabs")
    if not spool.is_dir():
        return rows
    try:
        for user_file in spool.iterdir():
            try:
                content = user_file.read_text(encoding="utf-8", errors="replace")
            except (OSError, PermissionError):
                continue
            for line in content.splitlines():
                s = line.strip()
                if not s or s.startswith("#"):
                    continue
                rows.append({"user": user_file.name, "line": s})
    except (OSError, PermissionError):
        pass
    return rows


def _timers() -> list[dict[str, str]]:
    rc, out = _run(["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"])
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        # NEXT LEFT LAST PASSED UNIT ACTIVATES
        parts = line.strip().split(None, 5)
        if len(parts) < 6:
            continue
        rows.append({
            "next": parts[0] + " " + parts[1] if parts[0] != "n/a" else "n/a",
            "left": parts[2],
            "unit": parts[4] if len(parts) > 4 else "",
            "activates": parts[5] if len(parts) > 5 else "",
        })
    return rows


# Standard SUID/SGID basenames we expect on Ubuntu — anything outside is flagged.
# We match on basename because Ubuntu has /bin → /usr/bin symlinks and we want
# both spellings to count as "expected".
EXPECTED_SUID_NAMES = {
    "at", "chage", "chfn", "chsh", "expiry", "gpasswd", "mount", "newgrp",
    "passwd", "pkexec", "su", "sudo", "umount", "fusermount3", "fusermount",
    "ssh-keysign", "polkit-agent-helper-1", "snap-confine", "snap-update-ns",
    "pam_extrausers_chkpwd", "unix_chkpwd", "ntfs-3g", "dbus-daemon-launch-helper",
    "crontab", "dotlockfile", "expiry", "wall", "write", "bsd-write",
    "ssh-agent",  # SGID
    "utempter",  # SGID under libexec
    "needrestart",  # commonly SGID
    "Xorg.wrap", "mlocate", "postdrop", "postqueue",
}


_SUID_ROOTS = ("/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/local", "/opt", "/bin", "/sbin")


def _suid_scan() -> list[dict[str, Any]]:
    now = time.time()
    if _SUID_CACHE["rows"] and (now - _SUID_CACHE["ts"] < _SUID_TTL):
        return _SUID_CACHE["rows"]
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    for root in _SUID_ROOTS:
        rp = Path(root)
        if not rp.is_dir():
            continue
        try:
            for path in rp.rglob("*"):
                try:
                    if path.is_symlink() or not path.is_file():
                        continue
                    st = path.lstat()
                except (OSError, PermissionError):
                    continue
                if not (st.st_mode & (stat.S_ISUID | stat.S_ISGID)):
                    continue
                full = str(path)
                # Dedupe via realpath so /bin and /usr/bin don't both list the same inode.
                try:
                    real = str(path.resolve())
                except OSError:
                    real = full
                if real in seen:
                    continue
                seen.add(real)
                rows.append({
                    "path": full,
                    "mode": oct(st.st_mode & 0o7777),
                    "uid": st.st_uid,
                    "size": st.st_size,
                    "suid": bool(st.st_mode & stat.S_ISUID),
                    "sgid": bool(st.st_mode & stat.S_ISGID),
                    "expected": Path(full).name in EXPECTED_SUID_NAMES,
                })
        except (OSError, PermissionError):
            continue
    rows.sort(key=lambda r: (r["expected"], r["path"]))
    _SUID_CACHE["ts"] = now
    _SUID_CACHE["rows"] = rows
    return rows


def collect() -> dict[str, Any]:
    sys_cron = _system_cron()
    usr_cron = _user_cron()
    timers = _timers()
    suid = _suid_scan()
    return {
        "system_cron": sys_cron,
        "user_cron": usr_cron,
        "timers": timers,
        "suid": suid,
        "suid_total": len(suid),
        "suid_unexpected": sum(1 for s in suid if not s["expected"]),
    }
