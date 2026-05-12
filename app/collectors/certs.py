"""TLS certificate expiry scanner.

Walks well-known cert paths and pulls notAfter using `openssl x509 -noout -dates`.
"""
from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Scan these locations; skip private keys.
# Server certs typically live in these dirs. /etc/ssl/certs is intentionally
# excluded — it's the OS trust store (CA roots), not server certs.
SCAN_DIRS = [
    "/etc/letsencrypt/live",
    "/etc/letsencrypt/archive",
    "/etc/nginx",
    "/etc/caddy",
    "/etc/apache2",
    "/etc/traefik",
    "/var/lib/caddy",
    "/var/lib/acme",
    "/var/lib/docker/volumes",  # many compose stacks store certs in named volumes
]

CERT_GLOBS = ("*.pem", "*.crt", "*.cer", "fullchain*", "cert*.crt", "cert.pem")

# Hard cap to keep scans fast & avoid OOM on big trees
MAX_FILES = 200

# Cache cert scan for 1 hour - openssl invocations add up
_CACHE: dict[str, Any] = {"ts": 0.0, "data": None}
_TTL = 3600
import time as _time

# Cache cert scan for 1 hour - openssl invocations add up
_CACHE: dict[str, Any] = {"ts": 0.0, "data": None}
_TTL = 3600
import time as _time


def _run(argv: list[str], timeout: int = 5) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _walk(root: Path):
    """Like os.walk but swallows permission errors at every level."""
    try:
        entries = list(root.iterdir())
    except (OSError, PermissionError):
        return
    for entry in entries:
        try:
            if entry.is_symlink():
                # Don't follow symlinks during traversal (loops + permission issues)
                continue
        except (OSError, PermissionError):
            continue
        try:
            if entry.is_dir():
                yield from _walk(entry)
                continue
        except (OSError, PermissionError):
            continue
        try:
            if entry.is_file():
                yield entry
        except (OSError, PermissionError):
            continue


def _is_dir_safe(p: Path) -> bool:
    try:
        return p.is_dir()
    except (OSError, PermissionError):
        return False


def _candidates() -> list[Path]:
    found: list[Path] = []
    seen: set[str] = set()
    for d in SCAN_DIRS:
        dp = Path(d)
        if not _is_dir_safe(dp):
            continue
        for p in _walk(dp):
            if "privkey" in p.name or "private" in p.name:
                continue
            # match against the cert globs
            if not any(p.match(g) for g in CERT_GLOBS):
                continue
            try:
                real = str(p.resolve())
            except OSError:
                real = str(p)
            if real in seen:
                continue
            seen.add(real)
            found.append(p)
            if len(found) >= MAX_FILES:
                return found
    return found


def _parse_cert(path: Path) -> dict[str, Any] | None:
    rc, out = _run(["openssl", "x509", "-in", str(path), "-noout", "-subject", "-issuer", "-dates", "-ext", "subjectAltName"])
    if rc != 0:
        return None
    subj = ""
    issuer = ""
    not_before = ""
    not_after = ""
    sans: list[str] = []
    for line in out.splitlines():
        if line.startswith("subject="):
            subj = line[len("subject="):].strip()
        elif line.startswith("issuer="):
            issuer = line[len("issuer="):].strip()
        elif line.startswith("notBefore="):
            not_before = line[len("notBefore="):].strip()
        elif line.startswith("notAfter="):
            not_after = line[len("notAfter="):].strip()
        elif "DNS:" in line:
            sans = [s.strip().replace("DNS:", "") for s in re.split(r"[,\s]+", line) if "DNS:" in s]
    if not not_after:
        return None
    try:
        # openssl format: "Aug  5 12:34:56 2025 GMT"
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    days = (expiry - datetime.now(timezone.utc)).days
    return {
        "path": str(path),
        "subject": subj,
        "issuer": issuer,
        "not_before": not_before,
        "not_after": not_after,
        "days_until_expiry": days,
        "expired": days < 0,
        "soon": 0 <= days <= 30,
        "sans": sans[:10],
    }


def collect(force: bool = False) -> dict[str, Any]:
    now = _time.time()
    if not force and _CACHE["data"] is not None and (now - _CACHE["ts"] < _TTL):
        d = dict(_CACHE["data"])
        d["cached"] = True
        d["age_seconds"] = int(now - _CACHE["ts"])
        return d
    # If openssl missing, bail
    rc, _ = _run(["openssl", "version"], timeout=3)
    if rc != 0:
        return {"available": False, "certs": []}
    certs: list[dict[str, Any]] = []
    for p in _candidates():
        info = _parse_cert(p)
        if info:
            certs.append(info)
    # Dedupe by (subject, not_after) — symlink farms produce many copies
    dedup: dict[tuple[str, str], dict[str, Any]] = {}
    for c in certs:
        key = (c["subject"], c["not_after"])
        if key not in dedup:
            dedup[key] = c
    out_list = sorted(dedup.values(), key=lambda c: c["days_until_expiry"])
    data = {
        "available": True,
        "certs": out_list,
        "expired": sum(1 for c in out_list if c["expired"]),
        "soon": sum(1 for c in out_list if c["soon"]),
        "total": len(out_list),
        "cached": False,
        "age_seconds": 0,
    }
    _CACHE["ts"] = now
    _CACHE["data"] = data
    return data
