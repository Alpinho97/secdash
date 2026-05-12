"""Per-user shell-history collector.

Reads ~/.bash_history and ~/.zsh_history for every UID>=1000 with a real shell.
Requires the dashboard process to have read access to those files (root).
"""
from __future__ import annotations

import pwd
import re
from pathlib import Path
from typing import Any

MAX_COMMANDS_PER_USER = 200

# Commands worth highlighting in the UI.
HIGHLIGHT_PATTERNS = [
    (re.compile(r"^\s*sudo\b"), "sudo"),
    (re.compile(r"\bpasswd\b"), "passwd"),
    (re.compile(r"chmod\s+[0-7]*777"), "chmod 777"),
    (re.compile(r"(curl|wget)\s.*\|\s*(sudo\s+)?(sh|bash)\b"), "pipe-to-shell"),
    (re.compile(r"\bnc\s+-l"), "nc listener"),
    (re.compile(r"\bssh-keygen\b"), "ssh-keygen"),
    (re.compile(r"^\s*history\s+-c\b"), "history wipe"),
    (re.compile(r"unset\s+HISTFILE"), "histfile unset"),
    (re.compile(r"\brm\s+-rf\s+/"), "rm -rf /"),
    (re.compile(r"/etc/(passwd|shadow|sudoers)"), "sensitive /etc edit"),
    (re.compile(r"\bdd\s+if=.*\bof=/dev/"), "dd to device"),
]

# zsh extended_history: ": <epoch>:<duration>;<command>"
RE_ZSH_EXT = re.compile(r"^:\s*(?P<ts>\d+):\d+;(?P<cmd>.*)$")

# bash with HISTTIMEFORMAT: a line "#<epoch>" precedes each command
RE_BASH_TS = re.compile(r"^#(\d{10})$")


def _classify(cmd: str) -> list[str]:
    tags = []
    for pat, tag in HIGHLIGHT_PATTERNS:
        if pat.search(cmd):
            tags.append(tag)
    return tags


def _read_bash(path: Path) -> list[dict[str, Any]]:
    try:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8", errors="replace")
    except (PermissionError, OSError):
        return []
    entries: list[dict[str, Any]] = []
    pending_ts: str = ""
    for line in text.splitlines():
        if not line.strip():
            continue
        m = RE_BASH_TS.match(line)
        if m:
            pending_ts = m.group(1)
            continue
        cmd = line.rstrip()
        entries.append({"ts": pending_ts, "cmd": cmd, "tags": _classify(cmd)})
        pending_ts = ""
    return entries[-MAX_COMMANDS_PER_USER:]


def _read_zsh(path: Path) -> list[dict[str, Any]]:
    try:
        if not path.is_file():
            return []
        # zsh history may have non-UTF8 metabytes
        raw = path.read_bytes()
    except (PermissionError, OSError):
        return []
    text = raw.decode("utf-8", errors="replace")
    entries: list[dict[str, Any]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        m = RE_ZSH_EXT.match(line)
        if m:
            cmd = m.group("cmd").rstrip()
            entries.append({"ts": m.group("ts"), "cmd": cmd, "tags": _classify(cmd)})
        else:
            cmd = line.rstrip()
            entries.append({"ts": "", "cmd": cmd, "tags": _classify(cmd)})
    return entries[-MAX_COMMANDS_PER_USER:]


def _real_users() -> list[pwd.struct_passwd]:
    users = []
    for u in pwd.getpwall():
        if u.pw_uid < 1000 or u.pw_uid >= 65534:
            continue
        if not u.pw_shell or u.pw_shell.endswith(("nologin", "false")):
            continue
        users.append(u)
    return sorted(users, key=lambda u: u.pw_name)


def collect() -> dict[str, Any]:
    result: list[dict[str, Any]] = []
    for u in _real_users():
        home = Path(u.pw_dir)
        bash = _read_bash(home / ".bash_history")
        zsh = _read_zsh(home / ".zsh_history")
        # Merge, preserving order; zsh first then bash so newest is at the bottom of each block.
        all_entries = bash + zsh
        flagged = [e for e in all_entries if e["tags"]]
        result.append({
            "user": u.pw_name,
            "uid": u.pw_uid,
            "shell": u.pw_shell,
            "home": str(home),
            "bash_count": len(bash),
            "zsh_count": len(zsh),
            "flagged_count": len(flagged),
            "entries": all_entries,
            "flagged": flagged[-50:][::-1],
        })
    return {"users": result, "total_users": len(result)}
