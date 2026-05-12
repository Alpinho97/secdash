"""Docker container inventory + image age."""
from __future__ import annotations

import json
import subprocess
from datetime import datetime, timezone
from typing import Any


def _run(argv: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return 127, ""


def _docker_available() -> bool:
    rc, _ = _run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=5)
    return rc == 0


def _ps() -> list[dict[str, str]]:
    rc, out = _run(["docker", "ps", "-a", "--format", "{{json .}}"], timeout=15)
    if rc != 0:
        return []
    rows: list[dict[str, str]] = []
    for line in out.splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows


def _compose_labels(container_id: str) -> dict[str, str]:
    """Read compose labels from a container. Returns project, working_dir, config_files, service."""
    if not container_id:
        return {}
    rc, out = _run([
        "docker", "inspect", container_id,
        "--format",
        '{{index .Config.Labels "com.docker.compose.project"}}|'
        '{{index .Config.Labels "com.docker.compose.project.working_dir"}}|'
        '{{index .Config.Labels "com.docker.compose.project.config_files"}}|'
        '{{index .Config.Labels "com.docker.compose.service"}}'
    ], timeout=5)
    if rc != 0 or not out.strip():
        return {}
    parts = out.strip().split("|")
    if len(parts) != 4:
        return {}
    project, wdir, cfg_files, service = parts
    if not project:
        return {}
    return {
        "project": project,
        "working_dir": wdir,
        "config_files": cfg_files,
        "service": service,
    }


def _compose_labels(container_id: str) -> dict[str, str]:
    """Read compose labels from a container. Returns project, working_dir, config_files, service."""
    if not container_id:
        return {}
    rc, out = _run([
        "docker", "inspect", container_id,
        "--format",
        '{{index .Config.Labels "com.docker.compose.project"}}|'
        '{{index .Config.Labels "com.docker.compose.project.working_dir"}}|'
        '{{index .Config.Labels "com.docker.compose.project.config_files"}}|'
        '{{index .Config.Labels "com.docker.compose.service"}}'
    ], timeout=5)
    if rc != 0 or not out.strip():
        return {}
    parts = out.strip().split("|")
    if len(parts) != 4:
        return {}
    project, wdir, cfg_files, service = parts
    if not project:
        return {}
    return {
        "project": project,
        "working_dir": wdir,
        "config_files": cfg_files,
        "service": service,
    }


def _image_created(image_ref: str) -> str:
    rc, out = _run(["docker", "image", "inspect", image_ref, "--format", "{{.Created}}"], timeout=10)
    return out.strip() if rc == 0 else ""


def _age_days(iso_ts: str) -> int:
    if not iso_ts:
        return -1
    try:
        # Trim fractional seconds beyond microseconds and normalize Z
        ts = iso_ts.replace("Z", "+00:00")
        if "." in ts:
            head, _, tail = ts.partition(".")
            frac = "".join(c for c in tail if c.isdigit() or c in "+-")
            # Re-attach timezone suffix
            tz = ""
            for c in tail:
                if c in "+-":
                    tz = tail[tail.index(c):]
                    break
            if not tz and tail.endswith(":00"):
                tz = "+" + tail.split("+")[-1] if "+" in tail else ""
            ts = f"{head}.{frac[:6]}{tz}" if frac else f"{head}{tz}"
        dt = datetime.fromisoformat(ts)
        return (datetime.now(timezone.utc) - dt).days
    except (ValueError, IndexError):
        return -1


def collect() -> dict[str, Any]:
    if not _docker_available():
        return {"available": False, "containers": [], "stacks": []}
    ps = _ps()
    containers: list[dict[str, Any]] = []
    image_cache: dict[str, str] = {}
    for c in ps:
        img = c.get("Image", "")
        if img not in image_cache:
            image_cache[img] = _image_created(img)
        created = image_cache[img]
        age = _age_days(created)
        state = c.get("State", "")
        status = c.get("Status", "")
        health = ""
        if "(healthy)" in status:
            health = "healthy"
        elif "(unhealthy)" in status:
            health = "unhealthy"
        elif "(starting)" in status:
            health = "starting"
        cid = (c.get("ID") or "")[:12]
        compose = _compose_labels(cid)
        containers.append({
            "name": c.get("Names", ""),
            "image": img,
            "image_age_days": age,
            "image_created": created,
            "state": state,
            "status": status,
            "health": health,
            "ports": c.get("Ports", ""),
            "id": cid,
            "compose_project": compose.get("project", ""),
            "compose_working_dir": compose.get("working_dir", ""),
            "compose_config_files": compose.get("config_files", ""),
            "compose_service": compose.get("service", ""),
        })
    containers.sort(key=lambda r: (r["state"] != "running", r["compose_project"], r["name"]))

    # Group into stacks by compose project. Containers without a project end up as standalone.
    stacks_map: dict[str, dict[str, Any]] = {}
    standalone: list[dict[str, Any]] = []
    for c in containers:
        proj = c["compose_project"]
        if not proj:
            standalone.append(c)
            continue
        s = stacks_map.setdefault(proj, {
            "project": proj,
            "working_dir": c["compose_working_dir"],
            "config_files": c["compose_config_files"],
            "containers": [],
            "running": 0,
            "total": 0,
            "unhealthy": 0,
            "oldest_image_days": 0,
        })
        s["containers"].append(c)
        s["total"] += 1
        if c["state"] == "running":
            s["running"] += 1
        if c["health"] == "unhealthy":
            s["unhealthy"] += 1
        if c["image_age_days"] > s["oldest_image_days"]:
            s["oldest_image_days"] = c["image_age_days"]

    stacks = sorted(stacks_map.values(), key=lambda s: s["project"])
    running = sum(1 for c in containers if c["state"] == "running")
    unhealthy = sum(1 for c in containers if c["health"] == "unhealthy")
    old = sum(1 for c in containers if c["image_age_days"] >= 90)
    return {
        "available": True,
        "containers": containers,
        "stacks": stacks,
        "standalone": standalone,
        "total": len(containers),
        "running": running,
        "unhealthy": unhealthy,
        "old_images": old,
    }
