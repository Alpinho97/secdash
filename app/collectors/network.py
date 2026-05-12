"""Established TCP connections, NIC byte counters, tailscale status."""
from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

# Sample state for /proc/net/dev rate calculation
_NIC_PREV: dict[str, Any] = {"ts": 0.0, "counters": {}}


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


RE_PROC = re.compile(r'\("(?P<name>[^"]+)",pid=(?P<pid>\d+)')


def _established() -> list[dict[str, str]]:
    rc, out = _run(["ss", "-tnpH", "state", "established"])
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        # Recv-Q Send-Q Local Peer [Process]
        local = parts[2]
        peer = parts[3]
        pname = ppid = ""
        if len(parts) > 4 and parts[-1].startswith("users:"):
            m = RE_PROC.search(parts[-1])
            if m:
                pname = m.group("name")
                ppid = m.group("pid")
        rows.append({"local": local, "peer": peer, "process": pname, "pid": ppid})
    return rows


def _is_docker_iface(name: str) -> bool:
    """Docker bridges/veths are usually noise; filter by default."""
    return name.startswith(("veth", "br-", "docker")) or name.startswith("vnet")


def _is_docker_iface(name: str) -> bool:
    """Docker bridges/veths are usually noise; filter by default."""
    return name.startswith(("veth", "br-", "docker")) or name.startswith("vnet")


def _nic_counters() -> dict[str, dict[str, int]]:
    """Parse /proc/net/dev → {iface: {rx_bytes, tx_bytes, rx_pkts, tx_pkts}}."""
    out: dict[str, dict[str, int]] = {}
    try:
        with open("/proc/net/dev") as fh:
            lines = fh.readlines()
    except OSError:
        return out
    for line in lines[2:]:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        if name == "lo":
            continue
        cols = rest.split()
        if len(cols) < 16:
            continue
        try:
            out[name] = {
                "rx_bytes": int(cols[0]),
                "rx_pkts": int(cols[1]),
                "rx_errs": int(cols[2]),
                "tx_bytes": int(cols[8]),
                "tx_pkts": int(cols[9]),
                "tx_errs": int(cols[10]),
            }
        except (ValueError, IndexError):
            continue
    return out


def _nic_rates() -> list[dict[str, Any]]:
    """Compute per-NIC bytes/sec since last call."""
    now = time.time()
    cur = _nic_counters()
    prev_ts = _NIC_PREV["ts"]
    prev = _NIC_PREV["counters"]
    dt = max(now - prev_ts, 0.001) if prev_ts else 0
    rows: list[dict[str, Any]] = []
    for name, c in cur.items():
        rx_rate = tx_rate = 0.0
        if dt and name in prev:
            rx_rate = (c["rx_bytes"] - prev[name]["rx_bytes"]) / dt
            tx_rate = (c["tx_bytes"] - prev[name]["tx_bytes"]) / dt
            rx_rate = max(rx_rate, 0)
            tx_rate = max(tx_rate, 0)
        rows.append({
            "name": name,
            "is_docker": _is_docker_iface(name),
            "rx_bytes": c["rx_bytes"],
            "tx_bytes": c["tx_bytes"],
            "rx_pkts": c["rx_pkts"],
            "tx_pkts": c["tx_pkts"],
            "rx_errs": c["rx_errs"],
            "tx_errs": c["tx_errs"],
            "rx_rate": rx_rate,
            "tx_rate": tx_rate,
        })
    _NIC_PREV["ts"] = now
    _NIC_PREV["counters"] = cur
    # Sort: real NICs first, then docker ifaces by name
    rows.sort(key=lambda r: (r["is_docker"], r["name"]))
    return rows


def _tailscale() -> dict[str, Any]:
    rc, out = _run(["tailscale", "status", "--json"], timeout=10)
    if rc != 0 or not out.strip():
        return {"available": False}
    try:
        ts = json.loads(out)
    except json.JSONDecodeError:
        return {"available": False}
    self_node = ts.get("Self", {}) or {}
    peers = ts.get("Peer", {}) or {}
    peer_list = []
    for pubkey, p in peers.items():
        peer_list.append({
            "host": p.get("HostName", ""),
            "dns": p.get("DNSName", "").rstrip("."),
            "ip": (p.get("TailscaleIPs") or [""])[0],
            "os": p.get("OS", ""),
            "online": p.get("Online", False),
            "last_seen": p.get("LastSeen", ""),
            "exit_node": p.get("ExitNode", False),
        })
    peer_list.sort(key=lambda r: (not r["online"], r["host"]))
    return {
        "available": True,
        "backend_state": ts.get("BackendState", ""),
        "self_host": self_node.get("HostName", ""),
        "self_ip": (self_node.get("TailscaleIPs") or [""])[0],
        "magicdns_suffix": ts.get("MagicDNSSuffix", ""),
        "exit_node_status": ts.get("ExitNodeStatus", {}),
        "peers": peer_list,
        "online_peers": sum(1 for p in peer_list if p["online"]),
    }


def collect() -> dict[str, Any]:
    return {
        "connections": _established(),
        "connection_count": -1,  # filled below
        "nics": _nic_rates(),
        "tailscale": _tailscale(),
    }
