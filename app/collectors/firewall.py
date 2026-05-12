"""ufw + fail2ban state collector."""
from __future__ import annotations

import subprocess
from typing import Any


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


def _collect_ufw() -> dict[str, Any]:
    rc, out, err = _run(["ufw", "status", "verbose"])
    if rc != 0:
        return {"available": False, "error": err.strip() or out.strip(), "active": False, "rules": []}
    active = "Status: active" in out
    rules: list[str] = []
    capture = False
    for line in out.splitlines():
        if line.startswith("To"):
            capture = True
            continue
        if capture and line.strip() and not line.startswith("--"):
            rules.append(line.rstrip())
    return {"available": True, "active": active, "raw": out, "rules": rules}


def _collect_fail2ban() -> dict[str, Any]:
    rc_active, active_out, _ = _run(["systemctl", "is-active", "fail2ban"])
    state = active_out.strip() or "unknown"
    info: dict[str, Any] = {"state": state, "jails": [], "recent_log": []}
    if state == "active":
        rc, out, _ = _run(["fail2ban-client", "status"])
        jail_line = ""
        for line in out.splitlines():
            if "Jail list" in line:
                jail_line = line.split(":", 1)[-1].strip()
        jails = [j.strip() for j in jail_line.split(",") if j.strip()]
        jail_details: list[dict[str, Any]] = []
        for j in jails:
            rc2, out2, _ = _run(["fail2ban-client", "status", j])
            banned: list[str] = []
            total_failed = total_banned = 0
            for line in out2.splitlines():
                ll = line.strip()
                if ll.startswith("Banned IP list:"):
                    banned = [b for b in ll.split(":", 1)[1].strip().split() if b]
                elif ll.startswith("Total failed:"):
                    try:
                        total_failed = int(ll.split(":", 1)[1].strip())
                    except ValueError:
                        pass
                elif ll.startswith("Total banned:"):
                    try:
                        total_banned = int(ll.split(":", 1)[1].strip())
                    except ValueError:
                        pass
            jail_details.append({
                "name": j,
                "banned": banned,
                "total_failed": total_failed,
                "total_banned": total_banned,
            })
        info["jails"] = jail_details
    else:
        # Surface failure reason
        rc, out, _ = _run(["journalctl", "-u", "fail2ban", "--no-pager", "-n", "20"])
        info["recent_log"] = out.splitlines()[-20:]
    return info


def collect() -> dict[str, Any]:
    return {
        "ufw": _collect_ufw(),
        "fail2ban": _collect_fail2ban(),
    }
