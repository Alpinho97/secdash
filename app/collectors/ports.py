"""Listening-socket collector via `ss -tulpnH`."""
from __future__ import annotations

import re
import subprocess
from typing import Any

# Process column from ss: users:(("sshd",pid=1234,fd=3))
RE_PROC = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')

# Well-known: a public-bind on these isn't surprising
COMMON_PUBLIC = {"sshd", "docker-proxy", "tailscaled"}


def _split_addr(addr: str) -> tuple[str, str]:
    """Split 'ip:port' or '[::]:port' into (ip, port)."""
    if addr.startswith("["):
        host, _, port = addr.rpartition("]:")
        return host.lstrip("["), port
    host, _, port = addr.rpartition(":")
    return host, port


def collect() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["ss", "-tulpnH"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return {"error": str(e), "rows": []}

    rows: list[dict[str, Any]] = []
    for raw in proc.stdout.splitlines():
        parts = raw.split()
        if len(parts) < 5:
            continue
        netid = parts[0]
        # State column exists for TCP; UDP rows start without it.
        # ss -tulpnH columns: Netid State Recv-Q Send-Q LocalAddress:Port PeerAddress:Port Process
        # For UDP the "State" is "UNCONN".
        try:
            local_addr_col = parts[4]
        except IndexError:
            continue
        host, port = _split_addr(local_addr_col)
        proc_field = parts[-1] if parts[-1].startswith("users:") else ""
        pm = RE_PROC.search(proc_field)
        pname = pm.group("name") if pm else ""
        ppid = pm.group("pid") if pm else ""

        is_public = host in ("0.0.0.0", "::", "*")
        is_loopback = host in ("127.0.0.1", "::1")
        flagged = is_public and pname not in COMMON_PUBLIC

        rows.append({
            "proto": netid,
            "local_host": host or "?",
            "local_port": port or "?",
            "process": pname,
            "pid": ppid,
            "is_public": is_public,
            "is_loopback": is_loopback,
            "flagged": flagged,
        })

    rows.sort(key=lambda r: (not r["flagged"], r["proto"], int(r["local_port"]) if r["local_port"].isdigit() else 0))
    return {
        "rows": rows,
        "total": len(rows),
        "public_count": sum(1 for r in rows if r["is_public"]),
        "flagged_count": sum(1 for r in rows if r["flagged"]),
    }
