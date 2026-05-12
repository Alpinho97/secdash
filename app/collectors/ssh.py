"""SSH effective config + per-user authorized_keys."""
from __future__ import annotations

import base64
import hashlib
import pwd
import subprocess
from pathlib import Path
from typing import Any

# Interesting sshd_config keys to surface front-and-center
INTERESTING_KEYS = {
    "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
    "permitemptypasswords", "challengeresponseauthentication",
    "kbdinteractiveauthentication", "x11forwarding", "allowtcpforwarding",
    "gatewayports", "port", "addressfamily", "listenaddress",
    "allowusers", "allowgroups", "denyusers", "denygroups",
    "maxauthtries", "logingracetime", "clientaliveinterval",
    "usepam", "subsystem",
}

# Heuristic: any of these strings in a config value mark it as "loose"
LOOSE_VALUES = {
    "permitrootlogin": {"yes"},
    "passwordauthentication": {"yes"},
    "permitemptypasswords": {"yes"},
    "x11forwarding": {"yes"},
    "allowtcpforwarding": {"yes", "all"},
    "gatewayports": {"yes", "clientspecified"},
}


def _run(argv: list[str], timeout: int = 10) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _sshd_effective() -> dict[str, list[str]]:
    """`sshd -T` returns effective config. Requires root."""
    rc, out = _run(["sshd", "-T"])
    if rc != 0:
        return {}
    cfg: dict[str, list[str]] = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        parts = line.strip().split(None, 1)
        if len(parts) != 2:
            continue
        k = parts[0].lower()
        cfg.setdefault(k, []).append(parts[1])
    return cfg


def _key_fingerprint(blob_b64: str) -> str:
    try:
        raw = base64.b64decode(blob_b64)
        digest = hashlib.sha256(raw).digest()
        b64 = base64.b64encode(digest).rstrip(b"=").decode()
        return "SHA256:" + b64
    except Exception:
        return ""


def _key_bits(algo: str, blob_b64: str) -> int:
    """Approximate bit length. For ed25519 it's 256; for RSA decode the modulus."""
    if "ed25519" in algo:
        return 256
    if "ecdsa" in algo:
        return int("".join(c for c in algo if c.isdigit()) or "0")
    if "rsa" in algo:
        # Parse SSH wire format: 4-byte length-prefixed fields. Field 1 = algo,
        # field 2 = e (exponent), field 3 = n (modulus). bit-length of modulus.
        try:
            raw = base64.b64decode(blob_b64)
            i = 0
            for _ in range(3):
                if i + 4 > len(raw):
                    return 0
                length = int.from_bytes(raw[i:i+4], "big")
                i += 4
                if _ == 2:
                    n = raw[i:i+length]
                    # Strip leading 0x00 sign byte
                    while n and n[0] == 0:
                        n = n[1:]
                    return len(n) * 8
                i += length
        except Exception:
            return 0
    return 0


def _authorized_keys_for(home: Path) -> list[dict[str, Any]]:
    path = home / ".ssh" / "authorized_keys"
    try:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return []
    out: list[dict[str, Any]] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Optional "options" prefix can appear before the algo. Algos start with ssh-/ecdsa-/sk-
        parts = line.split()
        algo = blob = comment = options = ""
        for i, tok in enumerate(parts):
            if tok.startswith(("ssh-", "ecdsa-", "sk-")):
                if i > 0:
                    options = " ".join(parts[:i])
                algo = tok
                if i + 1 < len(parts):
                    blob = parts[i + 1]
                comment = " ".join(parts[i + 2:])
                break
        if not algo or not blob:
            continue
        bits = _key_bits(algo, blob)
        weak = (algo.startswith("ssh-rsa") and bits and bits < 3072) or algo == "ssh-dss"
        out.append({
            "algo": algo,
            "bits": bits,
            "fingerprint": _key_fingerprint(blob),
            "comment": comment,
            "options": options,
            "weak": weak,
            "no_comment": not comment.strip(),
        })
    return out


def _real_users():
    users = []
    for u in pwd.getpwall():
        if u.pw_uid >= 65534:
            continue
        if u.pw_uid < 1000 and u.pw_name != "root":
            continue
        if not u.pw_shell or u.pw_shell.endswith(("nologin", "false")):
            if u.pw_name != "root":
                continue
        users.append(u)
    return sorted(users, key=lambda u: (u.pw_uid != 0, u.pw_name))


def collect() -> dict[str, Any]:
    cfg = _sshd_effective()
    # Pick only interesting keys for display, but keep the full dict in raw
    short: dict[str, str] = {}
    findings: list[str] = []
    for k in sorted(INTERESTING_KEYS):
        if k not in cfg:
            continue
        vals = cfg[k]
        short[k] = ", ".join(vals)
        if k in LOOSE_VALUES and any(v.lower() in LOOSE_VALUES[k] for v in vals):
            findings.append(f"{k}={vals[0]}")

    users: list[dict[str, Any]] = []
    for u in _real_users():
        keys = _authorized_keys_for(Path(u.pw_dir))
        users.append({
            "user": u.pw_name,
            "uid": u.pw_uid,
            "home": u.pw_dir,
            "keys": keys,
            "key_count": len(keys),
            "weak_count": sum(1 for k in keys if k["weak"]),
            "no_comment_count": sum(1 for k in keys if k["no_comment"]),
        })

    total_keys = sum(u["key_count"] for u in users)
    weak_keys = sum(u["weak_count"] for u in users)
    return {
        "config": short,
        "findings": findings,
        "users": users,
        "total_keys": total_keys,
        "weak_keys": weak_keys,
    }
