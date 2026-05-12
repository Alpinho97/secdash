"""Action runner for dashboard write-actions (e.g. docker compose update).

Design:
- Each action becomes a Job with a unique id, kept in memory in a bounded ring.
- Jobs run in a thread (subprocess.Popen blocking from a worker thread is fine
  — uvicorn is async + this is rare/short-lived).
- A per-target lock prevents two updates of the same stack running at once.
- Output is line-buffered and exposed via /api/jobs/<id> + a streaming endpoint.

Security:
- Never accept arbitrary commands from the request body. The action HANDLERS
  decide what to run based on a known compose project label we read from
  `docker inspect` ourselves at action-trigger time.
- The compose project's working_dir is verified to exist and contain a
  docker-compose file before exec.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

# Per-target locks: only one update per stack/image at a time
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_LOCK = threading.Lock()

# Bounded job history
_JOBS: dict[str, "Job"] = {}
_JOBS_ORDER: deque[str] = deque(maxlen=100)
_JOBS_LOCK = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    with _LOCKS_LOCK:
        return _LOCKS.setdefault(key, threading.Lock())


@dataclass
class Job:
    id: str
    kind: str          # "compose_update" | "image_pull"
    target: str        # compose project name or image ref
    label: str         # human-readable description
    status: str = "pending"  # pending | running | success | failed | locked
    started_at: float = 0.0
    finished_at: float = 0.0
    exit_code: int | None = None
    lines: list[dict[str, Any]] = field(default_factory=list)  # [{ts, stream, text}]
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "label": self.label,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "duration": (self.finished_at - self.started_at) if self.finished_at else (time.time() - self.started_at if self.started_at else 0),
            "exit_code": self.exit_code,
            "lines": self.lines,
            "line_count": len(self.lines),
            "error": self.error,
        }


def _register_job(job: Job) -> None:
    with _JOBS_LOCK:
        _JOBS[job.id] = job
        _JOBS_ORDER.append(job.id)
        # Evict the job that fell off the deque, if any
        ids_in_deque = set(_JOBS_ORDER)
        for jid in list(_JOBS.keys()):
            if jid not in ids_in_deque:
                _JOBS.pop(jid, None)


def get_job(job_id: str) -> Job | None:
    with _JOBS_LOCK:
        return _JOBS.get(job_id)


def list_jobs(limit: int = 30) -> list[dict[str, Any]]:
    with _JOBS_LOCK:
        ids = list(_JOBS_ORDER)[-limit:][::-1]
        return [_JOBS[i].to_dict() for i in ids if i in _JOBS]


def _run_steps(job: Job, steps: list[list[str]], cwd: str | None = None, env_extra: dict[str, str] | None = None) -> None:
    """Run a sequence of commands; stop on first failure. Appends lines into job.lines."""
    env = os.environ.copy()
    if env_extra:
        env.update(env_extra)
    job.started_at = time.time()
    job.status = "running"
    for argv in steps:
        job.lines.append({"ts": time.time(), "stream": "meta", "text": "$ " + " ".join(shlex.quote(a) for a in argv)})
        try:
            proc = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=1,
                text=True,
            )
        except FileNotFoundError as e:
            job.lines.append({"ts": time.time(), "stream": "err", "text": f"exec failed: {e}"})
            job.status = "failed"
            job.exit_code = 127
            job.error = str(e)
            job.finished_at = time.time()
            return
        assert proc.stdout is not None
        for line in proc.stdout:
            job.lines.append({"ts": time.time(), "stream": "out", "text": line.rstrip()})
        rc = proc.wait()
        job.lines.append({"ts": time.time(), "stream": "meta", "text": f"(exit {rc})"})
        if rc != 0:
            job.status = "failed"
            job.exit_code = rc
            job.finished_at = time.time()
            return
    job.status = "success"
    job.exit_code = 0
    job.finished_at = time.time()


def _submit(kind: str, target: str, label: str, lock_key: str, runner: Callable[[Job], None]) -> Job:
    job = Job(id=uuid.uuid4().hex[:12], kind=kind, target=target, label=label)
    _register_job(job)

    lock = _lock_for(lock_key)
    if not lock.acquire(blocking=False):
        job.status = "locked"
        job.error = "Another action for the same target is already running."
        job.started_at = time.time()
        job.finished_at = time.time()
        return job

    def _wrapper():
        try:
            runner(job)
        finally:
            lock.release()

    threading.Thread(target=_wrapper, daemon=True, name=f"action-{kind}-{target}").start()
    return job


# ---------- Actions ----------

def update_compose_stack(project: str, working_dir: str) -> Job:
    """Pull latest images for a compose stack and restart it."""
    label = f"Update compose stack: {project}"
    # Verify working_dir
    wd = Path(working_dir)
    if not project or not wd.is_dir():
        job = Job(id=uuid.uuid4().hex[:12], kind="compose_update", target=project, label=label,
                  status="failed", error=f"working_dir not found: {working_dir}",
                  started_at=time.time(), finished_at=time.time())
        _register_job(job)
        return job
    # Sanity check that a compose file exists
    if not any((wd / n).is_file() for n in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")):
        job = Job(id=uuid.uuid4().hex[:12], kind="compose_update", target=project, label=label,
                  status="failed", error=f"no docker-compose file in {working_dir}",
                  started_at=time.time(), finished_at=time.time())
        _register_job(job)
        return job

    def _run(job: Job) -> None:
        steps = [
            ["docker", "compose", "-p", project, "pull"],
            ["docker", "compose", "-p", project, "up", "-d", "--remove-orphans"],
        ]
        _run_steps(job, steps, cwd=str(wd))

    return _submit("compose_update", project, label, f"compose:{project}", _run)


def pull_image(image: str) -> Job:
    """Pull a single image (no restart — caller has to handle that for standalone containers)."""
    label = f"Pull image: {image}"
    if "/" in image and "\x00" in image or " " in image:
        job = Job(id=uuid.uuid4().hex[:12], kind="image_pull", target=image, label=label,
                  status="failed", error="invalid image ref",
                  started_at=time.time(), finished_at=time.time())
        _register_job(job)
        return job

    def _run(job: Job) -> None:
        _run_steps(job, [["docker", "pull", image]])

    return _submit("image_pull", image, label, f"image:{image}", _run)


def restart_container(name: str) -> Job:
    """Restart a single non-compose container after image pull."""
    label = f"Restart container: {name}"
    if not name or any(c in name for c in (" ", ";", "&", "|", "$", "`", "\n", "\x00")):
        job = Job(id=uuid.uuid4().hex[:12], kind="container_restart", target=name, label=label,
                  status="failed", error="invalid container name",
                  started_at=time.time(), finished_at=time.time())
        _register_job(job)
        return job

    def _run(job: Job) -> None:
        _run_steps(job, [["docker", "restart", name]])

    return _submit("container_restart", name, label, f"container:{name}", _run)
