# secdash

A lightweight, read-only **security dashboard** for Linux hosts.
Built for homelab and small-fleet operators who want a single page to answer
"is anything weird on this box?" without setting up Grafana + Prometheus.

Designed to live on your **Tailnet** — no public exposure, no auth layer needed
(tailnet ACLs are the gate).

## Features

| Page          | What it shows                                                       |
|---------------|---------------------------------------------------------------------|
| **Overview**  | At-a-glance status cards + attention banner (failed services, reboot needed, security updates, etc.) |
| **System**    | Live CPU / RAM / load / disks with bars, polls every 2s             |
| **Processes** | Top processes by CPU% and RSS, live                                 |
| **Sessions**  | `who` + `last` + sudo audit (commands run, failed authentications)  |
| **Network**   | Live per-NIC byte rates, Tailscale peers, ESTABLISHED TCP connections |
| **Auth**      | SSH failed/accepted logins last 24h with top attacker IPs           |
| **SSH**       | Effective `sshd -T` config + per-user `authorized_keys` with fingerprints, flags weak RSA |
| **Ports**     | Listening sockets via `ss -tulpnH` with flagged public binds        |
| **Firewall**  | ufw rules + fail2ban jails (or failure reason if it's down)         |
| **Docker**    | Container inventory grouped by compose stack, image age, **"⟳ pull + up -d" buttons per stack**, "Update ALL" |
| **Updates**   | apt upgradable packages + debsecan CVEs (cached 1h)                 |
| **Certs**     | TLS server certificates with days-until-expiry                      |
| **Persistence** | SUID/SGID inventory vs Ubuntu baseline, cron jobs, systemd timers |
| **Host**      | Failed systemd units, kernel + reboot-required, time-sync, journald volume |
| **History**   | Per-user `~/.bash_history` + `~/.zsh_history` with high-signal pattern matching |

Plus JSON APIs (`/api/<page>`) for every page.

## One-liner install

On any Ubuntu/Debian host that's already on your tailnet:

```bash
curl -fsSL https://raw.githubusercontent.com/Alpinho97/secdash/main/install.sh | sudo bash
```

This:
1. Installs `git`, `python3-venv`, `debsecan`.
2. Auto-detects the host's tailscale0 IP and binds to it (falls back to `127.0.0.1` if Tailscale isn't running — reach via SSH tunnel in that case).
3. Clones into `/opt/secdash`, creates a venv, installs FastAPI + uvicorn.
4. Writes a systemd unit, enables and starts it.
5. Verifies `GET /healthz` returns 200.

Open `http://<tailnet-ip>:8765/` from anywhere on your tailnet.

### Installer options

```bash
# Custom port
curl -fsSL .../install.sh | sudo bash -s -- --port 9000

# Force a specific bind IP (skip tailscale auto-detect)
curl -fsSL .../install.sh | sudo bash -s -- --bind 10.0.0.5

# Skip debsecan (no CVE data, faster install)
curl -fsSL .../install.sh | sudo bash -s -- --no-debsecan

# Install a specific git ref
curl -fsSL .../install.sh | sudo bash -s -- --ref v1.0.0

# Uninstall
curl -fsSL .../install.sh | sudo bash -s -- --uninstall
```

## Manage

```bash
sudo systemctl status secdash
sudo systemctl restart secdash
sudo journalctl -u secdash -f

# Change bind/port without re-running installer:
sudo $EDITOR /etc/secdash/secdash.env
sudo systemctl restart secdash
```

## Security model

- **Tailnet-bound by default.** Your tailnet ACL is the auth gate. If you'd
  rather expose it publicly, layer your own reverse proxy + auth in front.
- **Read-only by default.** The only write actions are the Docker
  "update stack" buttons (one-click `docker compose pull && up -d` per project).
  Every action requires a browser confirm dialog and is recorded as a job
  with full log output.
- **No shell interpolation.** All collectors use `subprocess.run([...], shell=False)`
  with fixed argv. Project names + container names are whitelist-validated.
- **Trust boundary for actions:** the compose `working_dir` is *never* taken
  from the request — the server re-reads it from `docker inspect` based on
  the project name, so a caller can't redirect updates to an arbitrary path.
- **Runs as root.** Required to read `/var/log/auth.log` (mode 640
  `syslog:adm`), `~user/.bash_history` (mode 600), `sshd -T` output, AppArmor
  status, etc. The systemd unit applies `ProtectSystem=strict`,
  `ProtectHome=read-only`, `NoNewPrivileges`, and other hardening flags.

## How it works

```
┌───────────────────────────────────────────────────────────────┐
│  FastAPI app (uvicorn, single worker, root)                   │
│    ├── routes  /, /system, /docker, …                         │
│    ├── routes  /api/<page>  (JSON)                            │
│    └── routes  /api/actions/* + /api/jobs (write actions)     │
│                                                               │
│  Collectors — pure stdlib + parsed shell-tool output:         │
│    auth.py        journalctl _COMM=sshd                       │
│    ports.py       ss -tulpnH                                  │
│    firewall.py    ufw status / fail2ban-client                │
│    updates.py     apt list --upgradable / debsecan (1h cache) │
│    history.py     /home/*/.bash_history + .zsh_history        │
│    system.py      /proc/stat /proc/meminfo shutil.disk_usage  │
│    sessions.py    who / last / lastb / journalctl _COMM=sudo  │
│    network.py     /proc/net/dev / ss -tnp / tailscale --json  │
│    docker.py      docker ps + inspect (compose labels)        │
│    ssh.py         sshd -T / authorized_keys parser            │
│    host.py        systemctl --failed / dpkg-query / aa-status │
│    persistence.py SUID scan / systemd timers / cron (10m cache)│
│    processes.py   /proc/<pid>/stat /proc/<pid>/status         │
│    certs.py       openssl x509 (1h cache)                     │
└───────────────────────────────────────────────────────────────┘
```

No database. No external API calls (debsecan reaches out to the Debian
security tracker; everything else is local).

## Requirements

- Ubuntu 22.04 / 24.04 (other Debian-based distros likely work, untested)
- Python 3.10+
- systemd
- Optional: Tailscale (for auto-detection of bind IP)
- Optional: Docker (for `/docker` page + update buttons)
- Optional: fail2ban, ufw, debsecan (the relevant pages just say "unavailable" if missing)

## Development

```bash
git clone https://github.com/Alpinho97/secdash.git
cd secdash
python3 -m venv .venv
.venv/bin/pip install fastapi "uvicorn[standard]" jinja2
.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8765
```

Many collectors need root to read `/var/log/auth.log` and other users'
home dirs; you'll see empty data for those pages when running as a
non-root user.

## License

MIT — see [LICENSE](LICENSE).
