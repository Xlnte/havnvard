#!/usr/bin/env bash
set -euo pipefail
sudo systemctl disable --now \
  havnvard-infra126-a.timer \
  havnvard-infra126-b.timer \
  havnvard-infra126-c.timer \
  havnvard-infra126-d.timer \
  havnvard-infra126-e.timer \
  havnvard-infra126-monitor.timer
