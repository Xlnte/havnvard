# HavnVard — Client (Agent) Install Guide

**Purpose:** install the HavnVard file-inventory **agent** on a new machine (e.g. an Ubuntu
client) so it appears in the central inventory alongside the server and the NAS.
**Audience:** whoever installs a new client (a fresh Sonnet CC session can execute this end-to-end).
**Last updated:** 20261109 (1.4.2: section 4B, no-root install).

---

## 1. Architecture — one server, 0+ clients (server + agent / hub-and-spoke)

| Role | Where | What it does |
|------|-------|--------------|
| **Server** (one) | the server `server-1` | Central Postgres (`havnvard` DB, `diskaudit` schema), dedup, daily report to PRESI, Grafana dashboard. Also inventories itself + SSH-crawls the NAS. |
| **Client / agent** (0+) | any Linux box | Runs `scan.py` locally on a timer, writes its file inventory **directly to the central DB over Tailscale**, tagged by a unique `--host` name. Nothing else. |

- Each machine is one row-set in `diskaudit.files` keyed by its `host` tag. The report/dedup/Grafana
  on the server automatically include every host that writes rows. No per-client server config.
- Trust boundary = the **Tailnet**. All clients must be on the approved Tailscale net; membership IS
  authorization (per CLAUDE.md). No app-level auth beyond the DB role below.

## 2. Files a client needs (that's all)

From `/opt/havnvard/` on the server:
- `scan.py` — the scanner (self-contained: stdlib + `psycopg`)
- `heartbeat.py` — imported by `scan.py`
- `scan_guard.py` — imported by `scan.py` (1.4.3: one scan per host+root lock, per-scan staging cleanup)
- `requirements.txt` — `psycopg[binary]>=3.2`

`scan.py` CLI: `--host <tag>` (REQUIRED unique per machine), `--root <path>` (default `/`),
`--dry-run`, `--batch-size N`, `--no-btime`, `--exclude <prefix>` (repeatable).

---

## 3. SERVER one-time prerequisites (do once, then every client reuses)

The central Postgres is currently **loopback-only** (`127.0.0.1:5432`), so remote clients can't reach
it yet. Two one-time server changes (both align with the Tailnet-is-trust posture):

### 3a. Make Postgres listen off-loopback
Bind to all interfaces (`0.0.0.0`, same as Ollama on this box) — **`pg_hba.conf` is the real access
gate**: it restricts *who* can connect (tailnet CIDR only + scram password), so the broad listen is
fine given the Tailnet-is-trust posture.
```
# postgresql.conf  (find via: sudo -u postgres psql -tAc 'show config_file')
listen_addresses = '0.0.0.0'

# pg_hba.conf  — append (tailnet CIDR only; scram password auth is the gate)
host  havnvard  diskaudit_agent  100.64.0.0/10  scram-sha-256
```
Then **restart** (changing `listen_addresses` needs a restart, not just reload):
`sudo systemctl restart postgresql`. Verify: `ss -tlnp | grep 5432` shows `0.0.0.0:5432`.

### 3b. Create a scoped agent DB role
Least-privilege role that can only touch the `diskaudit` schema:
```sql
CREATE ROLE diskaudit_agent LOGIN PASSWORD '<GENERATE — see note>';
GRANT USAGE ON SCHEMA diskaudit TO diskaudit_agent;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA diskaudit TO diskaudit_agent;
GRANT USAGE, SELECT               ON ALL SEQUENCES IN SCHEMA diskaudit TO diskaudit_agent;
ALTER DEFAULT PRIVILEGES IN SCHEMA diskaudit
  GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO diskaudit_agent;
```
> **Password:** generate a fresh strong password and **shelve it per the Password Shelf process**
> (new provisioned credential). Do not inline it in any tracked file. Same password is reused by all
> clients (or make one role per client if you prefer tighter revocation).

---

## 4. CLIENT install (per new Ubuntu machine)

Run **as the machine's admin**. Install dir: `/opt/diskaudit-agent`. Runs as **root** so it can read
every file's metadata.

```bash
# 4.1 — prerequisites
sudo apt-get update && sudo apt-get install -y python3-venv python3-pip rsync

# 4.2 — pull the agent files from the server (over Tailscale)
sudo mkdir -p /opt/diskaudit-agent && cd /opt/diskaudit-agent
sudo rsync -av havnvard@server-1.example.ts.net:/opt/havnvard/{scan.py,heartbeat.py,scan_guard.py,requirements.txt} .

# 4.3 — venv + deps
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt

# 4.4 — secret env (chmod 600, root-owned; NOT in git)
#   pick a UNIQUE host tag for THIS machine (lowercase, no spaces), e.g. ubuntu-desk-01
sudo tee /etc/diskaudit-agent.env >/dev/null <<'EOF'
POSTGRES_URL=postgresql://diskaudit_agent:<PASSWORD>@192.0.2.10:5432/havnvard
EOF
sudo chmod 600 /etc/diskaudit-agent.env

# 4.5 — SMOKE TEST first (cheap, bounded, no merge): scan a small dir, dry-run
sudo bash -c 'set -a; . /etc/diskaudit-agent.env; set +a; \
  /opt/diskaudit-agent/.venv/bin/python /opt/diskaudit-agent/scan.py \
  --host <CLIENTNAME> --root /etc --dry-run'
#   expect: "[diskaudit] scan_id=... host=<CLIENTNAME> ... dry_run=True" and no errors

# 4.6 — first REAL full scan (excludes pseudo-fs + network mounts)
sudo bash -c 'set -a; . /etc/diskaudit-agent.env; set +a; \
  /opt/diskaudit-agent/.venv/bin/python /opt/diskaudit-agent/scan.py \
  --host <CLIENTNAME> --root / \
  --exclude /proc --exclude /sys --exclude /dev --exclude /run \
  --exclude /snap --exclude /var/lib/docker --exclude /mnt --exclude /media'
```

### 4B — No-root install (user-space, no pip/venv/apt; used 20261109 on laptop-2, laptop-3, desktop-1)

For a machine where you are an ordinary user, have no root, and `pip`/`ensurepip` may be missing. Everything lives in
`~/diskaudit-agent/`; nothing is installed system-wide and no secret is written to disk.

```bash
# On the server: fetch wheels for the CLIENT's Python (3.12 shown; use 3.14 etc. to match `python3 --version` there)
mkdir -p /tmp/wheels && cd /tmp/wheels
/opt/havnvard/.venv/bin/pip download --only-binary=:all: --platform manylinux2014_x86_64 \
  --python-version 312 --dest . psycopg psycopg-binary typing_extensions
#   (typing_extensions is needed on 3.12; newer Pythons do not need it)

# Copy to the client and unzip the wheels into a private lib dir
ssh <CLIENT> 'mkdir -p ~/diskaudit-agent/lib ~/diskaudit-agent/logs'
scp /tmp/wheels/*.whl <CLIENT>:~/diskaudit-agent/
ssh <CLIENT> 'cd ~/diskaudit-agent && for w in *.whl; do python3 -m zipfile -e "$w" lib/; done'
scp /opt/havnvard/{scan.py,heartbeat.py,scan_guard.py} <CLIENT>:~/diskaudit-agent/
```

Run with `lib/` on the import path and the DSN injected through the environment. The password is **never stored on the
client**: pipe it from the server over ssh stdin into the process environment (`<PASSWORD>` below is a placeholder; the real value
is on the Password Shelf).

```bash
# From the server; reads the password from wherever you keep it and sends it on stdin only
ssh <CLIENT> 'read -r PW; cd ~/diskaudit-agent && \
  POSTGRES_URL="postgresql://diskaudit_agent:${PW}@192.0.2.10:5432/havnvard" \
  PYTHONPATH=$HOME/diskaudit-agent/lib \
  nohup python3 scan.py --host <CLIENTNAME> --root / --exclude /snap --exclude /var/lib/docker \
        --exclude /mnt --exclude /media > logs/scan.log 2>&1 &' <<< "$PW_FROM_SHELF"
```

- Scan a mounted NTFS/USB drive under `/run/media/...` by giving that path as `--root`: since 1.4.2 an explicit `--root` is never
  excluded by the default `/run` exclude (the log prints `default exclude /run waived`).
- As a non-root user the scan records only what that user can read; unreadable directories are `scan_errors` rows.
- 1.4.2 and later merge safely into a host with no prior rows. On 1.4.1 or older, set `PGOPTIONS='-c enable_nestloop=off'`
  for a first scan of a new host (otherwise the merge can spin for hours).
- Check progress from the server: `SELECT scan_id, status, files_scanned FROM diskaudit.scan_runs WHERE host='<CLIENTNAME>' ORDER BY scan_id DESC LIMIT 1;`

### 4.7 — systemd timer (recurring, daily)
```bash
sudo tee /etc/systemd/system/diskaudit-agent.service >/dev/null <<'EOF'
[Unit]
Description=HavnVard agent — local file inventory to central DB
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
EnvironmentFile=/etc/diskaudit-agent.env
WorkingDirectory=/opt/diskaudit-agent
ExecStart=/opt/diskaudit-agent/.venv/bin/python /opt/diskaudit-agent/scan.py \
  --host CLIENTNAME --root / \
  --exclude /proc --exclude /sys --exclude /dev --exclude /run \
  --exclude /snap --exclude /var/lib/docker --exclude /mnt --exclude /media
TimeoutStartSec=6h
EOF

sudo tee /etc/systemd/system/diskaudit-agent.timer >/dev/null <<'EOF'
[Unit]
Description=HavnVard agent daily inventory schedule
[Timer]
OnCalendar=*-*-* 06:00:00
Persistent=true
RandomizedDelaySec=1800
[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now diskaudit-agent.timer
```
> Replace **`CLIENTNAME`** in the unit with the machine's real tag before enabling.

---

## 5. Verify (from the SERVER)

```sql
-- rows landed for the new host
SELECT host, count(*), pg_size_pretty(sum(size_bytes))
FROM diskaudit.files WHERE host = '<CLIENTNAME>' GROUP BY host;

-- scan completed cleanly
SELECT host, status, finished_at FROM diskaudit.scan_runs
WHERE host = '<CLIENTNAME>' ORDER BY started_at DESC LIMIT 3;
```
Then the new host appears automatically in the daily PRESI report and the Grafana dashboard:
`https://server-1.example.ts.net:9452/d/diskaudit/diskaudit`

## 6. Notes / gotchas

- **Unique `--host` per machine** — this is the primary key dimension. Reusing a tag merges two
  machines' inventories. Use stable lowercase names (`ubuntu-desk-01`, not the transient hostname if it
  changes).
- **Runs as root** to read all inode metadata; it reads metadata only (path/size/mtime/owner), never
  file contents.
- **Excludes**: always exclude `/proc /sys /dev /run` (pseudo-fs) and `/mnt /media` + `/var/lib/docker`
  unless you specifically want those counted. Add `--exclude` for any network mount you don't own.
- **Dedup across hosts** is computed on the server (the dedup pass hashes files and groups them by
  content across all hosts) — a client only inventories; it does not dedup.
- **Client needs Tailscale up** to reach `192.0.2.10:5432`. If the tailnet is down the scan fails
  cleanly and retries next timer.
- To remove a client: disable its timer, then on the server
  `DELETE FROM diskaudit.files WHERE host='<CLIENTNAME>'` (and `scan_runs`).
