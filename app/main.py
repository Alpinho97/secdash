"""Security Dashboard — FastAPI entrypoint.

Read-only. Binds to the Tailscale interface only (see systemd unit).
"""
from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, HTTPException, Body, HTTPException, Body
from fastapi.responses import JSONResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.collectors import (
    auth, ports, firewall, updates, history,
    system as sysres,
    sessions, network, docker as dockerc, ssh as sshc,
    host as hostc, persistence, processes, certs,
)
from app import actions
from app import actions

BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

app = FastAPI(title="Security Dashboard", docs_url=None, redoc_url=None, openapi_url=None)
app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")


# -------- helpers --------

def _hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "?"


def _render(request: Request, name: str, ctx: dict[str, Any]) -> Response:
    """Render via Starlette 1.x signature: (request, name, context)."""
    return templates.TemplateResponse(request, name, ctx)


def _overview() -> dict[str, Any]:
    """Light overview context. Heavy/cacheable scans (SUID, certs) excluded."""
    return {
        "hostname": _hostname(),
        "auth": auth.collect(),
        "ports": ports.collect(),
        "firewall": firewall.collect(),
        "updates": updates.collect(),
        "history": history.collect(),
        "system": sysres.collect(sample_seconds=0.15),
        "host": hostc.collect(),
        "sessions": sessions.collect(),
        "docker": dockerc.collect(),
    }


# -------- HTML pages --------

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return _render(request, "index.html", _overview())


@app.get("/auth", response_class=HTMLResponse)
def page_auth(request: Request):
    return _render(request, "auth.html", {"data": auth.collect(), "hostname": _hostname()})


@app.get("/ports", response_class=HTMLResponse)
def page_ports(request: Request):
    return _render(request, "ports.html", {"data": ports.collect(), "hostname": _hostname()})


@app.get("/firewall", response_class=HTMLResponse)
def page_firewall(request: Request):
    return _render(request, "firewall.html", {"data": firewall.collect(), "hostname": _hostname()})


@app.get("/updates", response_class=HTMLResponse)
def page_updates(request: Request):
    return _render(request, "updates.html", {"data": updates.collect(), "hostname": _hostname()})


@app.get("/history", response_class=HTMLResponse)
def page_history(request: Request):
    return _render(request, "history.html", {"data": history.collect(), "hostname": _hostname()})


@app.get("/system", response_class=HTMLResponse)
def page_system(request: Request):
    return _render(request, "system.html", {"data": sysres.collect(sample_seconds=0.25), "hostname": _hostname()})


@app.get("/sessions", response_class=HTMLResponse)
def page_sessions(request: Request):
    return _render(request, "sessions.html", {"data": sessions.collect(), "hostname": _hostname()})


@app.get("/network", response_class=HTMLResponse)
def page_network(request: Request):
    return _render(request, "network.html", {"data": network.collect(), "hostname": _hostname()})


@app.get("/docker", response_class=HTMLResponse)
def page_docker(request: Request):
    return _render(request, "docker.html", {"data": dockerc.collect(), "hostname": _hostname()})


@app.get("/ssh", response_class=HTMLResponse)
def page_ssh(request: Request):
    return _render(request, "ssh.html", {"data": sshc.collect(), "hostname": _hostname()})


@app.get("/host", response_class=HTMLResponse)
def page_host(request: Request):
    return _render(request, "host.html", {"data": hostc.collect(), "hostname": _hostname()})


@app.get("/persistence", response_class=HTMLResponse)
def page_persistence(request: Request):
    return _render(request, "persistence.html", {"data": persistence.collect(), "hostname": _hostname()})


@app.get("/processes", response_class=HTMLResponse)
def page_processes(request: Request):
    return _render(request, "processes.html", {"data": processes.collect(), "hostname": _hostname()})


@app.get("/certs", response_class=HTMLResponse)
def page_certs(request: Request):
    return _render(request, "certs.html", {"data": certs.collect(), "hostname": _hostname()})


# -------- favicon --------

_FAVICON_SVG = (
    b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64">'
    b'<path d="M32 4 L58 14 V32 C58 48 46 58 32 60 C18 58 6 48 6 32 V14 Z" '
    b'fill="#161b22" stroke="#58a6ff" stroke-width="3"/>'
    b'<path d="M22 32 L29 39 L44 24" fill="none" stroke="#3fb950" '
    b'stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>'
    b'</svg>'
)


@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.svg", include_in_schema=False)
@app.get("/apple-touch-icon.png", include_in_schema=False)
@app.get("/apple-touch-icon-precomposed.png", include_in_schema=False)
def favicon():
    return Response(content=_FAVICON_SVG, media_type="image/svg+xml")


# -------- JSON APIs --------

@app.get("/api/auth")
def api_auth():
    return JSONResponse(auth.collect())


@app.get("/api/ports")
def api_ports():
    return JSONResponse(ports.collect())


@app.get("/api/firewall")
def api_firewall():
    return JSONResponse(firewall.collect())


@app.get("/api/updates")
def api_updates(force: bool = False):
    return JSONResponse(updates.collect(force=force))


@app.get("/api/history")
def api_history():
    return JSONResponse(history.collect())


@app.get("/api/system")
def api_system(sample: float = 0.25):
    sample = max(0.05, min(sample, 1.0))
    return JSONResponse(sysres.collect(sample_seconds=sample))


@app.get("/api/sessions")
def api_sessions():
    return JSONResponse(sessions.collect())


@app.get("/api/network")
def api_network():
    return JSONResponse(network.collect())


@app.get("/api/docker")
def api_docker():
    return JSONResponse(dockerc.collect())


@app.get("/api/ssh")
def api_ssh():
    return JSONResponse(sshc.collect())


@app.get("/api/host")
def api_host():
    return JSONResponse(hostc.collect())


@app.get("/api/persistence")
def api_persistence():
    return JSONResponse(persistence.collect())


@app.get("/api/processes")
def api_processes():
    return JSONResponse(processes.collect())


@app.get("/api/certs")
def api_certs(force: bool = False):
    return JSONResponse(certs.collect(force=force))


# -------- Action endpoints (write actions) --------

@app.post("/api/actions/compose/update")
def action_compose_update(payload: dict = Body(...)):
    """Pull + up -d a compose stack.

    Trust boundary: we DO NOT take the working_dir from the request.
    Instead we re-read it from docker labels for the named project,
    so a caller can't point us at an arbitrary path.
    """
    project = payload.get("project", "").strip()
    if not project or not all(c.isalnum() or c in "._-" for c in project):
        raise HTTPException(400, "invalid project name")
    d = dockerc.collect()
    stack = next((s for s in d.get("stacks", []) if s["project"] == project), None)
    if not stack:
        raise HTTPException(404, f"no running compose stack named {project!r}")
    job = actions.update_compose_stack(project, stack["working_dir"])
    return job.to_dict()


@app.post("/api/actions/compose/update-all")
def action_compose_update_all():
    """Trigger updates for every detected compose stack. One job per stack."""
    d = dockerc.collect()
    job_ids: list[dict[str, Any]] = []
    for stack in d.get("stacks", []):
        job = actions.update_compose_stack(stack["project"], stack["working_dir"])
        job_ids.append({"project": stack["project"], "job_id": job.id, "status": job.status})
    return {"jobs": job_ids}


@app.post("/api/actions/image/pull")
def action_image_pull(payload: dict = Body(...)):
    image = payload.get("image", "").strip()
    if not image:
        raise HTTPException(400, "missing image")
    job = actions.pull_image(image)
    return job.to_dict()


@app.post("/api/actions/container/restart")
def action_container_restart(payload: dict = Body(...)):
    name = payload.get("name", "").strip()
    if not name:
        raise HTTPException(400, "missing container name")
    # Verify the container actually exists before we run anything
    d = dockerc.collect()
    if not any(c["name"] == name for c in d.get("containers", [])):
        raise HTTPException(404, f"no such container: {name}")
    job = actions.restart_container(name)
    return job.to_dict()


@app.get("/api/jobs")
def api_jobs(limit: int = 30):
    return {"jobs": actions.list_jobs(limit=limit)}


@app.get("/api/jobs/{job_id}")
def api_job(job_id: str):
    job = actions.get_job(job_id)
    if not job:
        raise HTTPException(404, "no such job")
    return job.to_dict()


@app.get("/healthz")
def healthz():
    return {"ok": True}
