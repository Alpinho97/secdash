#!/usr/bin/env bash
# One-time setup: install gh CLI on this server.
# Run with: sudo bash _setup-gh.sh
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
  echo "Run with sudo." >&2
  exit 1
fi

if command -v gh >/dev/null; then
  echo "gh already installed: $(gh --version | head -n1)"
  exit 0
fi

echo "[1/3] Adding GitHub CLI apt repo"
install -m 0755 -d /etc/apt/keyrings
out=$(mktemp)
wget -qO "$out" https://cli.github.com/packages/githubcli-archive-keyring.gpg
install -m 0644 "$out" /etc/apt/keyrings/githubcli-archive-keyring.gpg
rm -f "$out"
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
  > /etc/apt/sources.list.d/github-cli.list

echo "[2/3] apt update + install"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y gh

echo "[3/3] Done."
gh --version | head -n1
echo
echo "Next: as your user, run 'gh auth login' (HTTPS + browser is easiest)."
