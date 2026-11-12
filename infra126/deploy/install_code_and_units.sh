#!/usr/bin/env bash
set -euo pipefail

SOURCE_DIR=${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}
DEST_DIR=${INFRA126_DEST_DIR:-/srv/ultraops/diskaudit/infra126}

if [[ $DEST_DIR != /srv/ultraops/diskaudit/infra126 ]]; then
  echo "Refusing unexpected destination: $DEST_DIR" >&2
  exit 2
fi

sudo install -d -o parker -g parker "$DEST_DIR"
sudo rsync -a --delete --chown=parker:parker "$SOURCE_DIR/" "$DEST_DIR/"
cd "$DEST_DIR"
sudo -u parker python3 -m venv .venv
sudo -u parker .venv/bin/pip install --upgrade pip
sudo -u parker .venv/bin/pip install -e '.[web,test]'
sudo -u parker env PYTHONPATH=src .venv/bin/pytest -q
sudo install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload

echo "Code and units installed. Timers remain disabled."
echo "Review INSTALLATION.md and run live acceptance before enabling anything."
