# Controlled Installation

**New HavnVard site (3.1.0+):** `schema/baseline.sql` in the repo root already creates every infra126 table, view
and function and seeds the mutable/immutable file rules. Skip §1 and §4 (they are for upgrading the original
deployment, and migration 001 seeds that deployment's host names), add your hosts' verification schedule as shown
in the README "Database" section, then continue at §5.
On a new site expect (number of hosts × 4) verification-schedule rows. `scripts/validate_live.py` still checks
for exactly 12 (the original three-host deployment), so its SLA-row check fails on other host counts until that is
fixed (Plane ticket filed with 3.1.0).

## 1. Do not install over an unknown prototype

Check whether the earlier prototype was applied:

```bash
psql "$POSTGRES_URL" -x -c "
SELECT table_name
FROM information_schema.tables
WHERE table_schema='diskaudit'
  AND table_name LIKE 'hash_%'
ORDER BY table_name;"
```

If prototype tables already contain production observations, do not drop them. Compare their columns to `migrations/001_infra126_core.sql` and write a reviewed upgrade migration.

## 2. Install the package without enabling timers

```bash
sudo install -d -o havnvard -g havnvard /opt/havnvard/infra126
rsync -a --delete ./INFRA-126-REBUILT/ /opt/havnvard/infra126/
cd /opt/havnvard/infra126
python3 -m venv .venv
.venv/bin/pip install --upgrade pip
.venv/bin/pip install -e '.[web,test]'
PYTHONPATH=src .venv/bin/pytest -q
```

`rsync --delete` above applies only to the dedicated INFRA-126 application directory. It must never target a scanned data directory.

## 3. Create configuration

```bash
sudo install -d -m 0750 /etc/havnvard
sudo install -m 0640 -o root -g havnvard config/infra126.env.example /etc/havnvard/infra126.env
sudo vi /etc/havnvard/infra126.env
sudo install -d -o havnvard -g havnvard /var/log/havnvard/infra126
```

Required adapters:

- `INFRA126_TG_COMMAND`
- `INFRA126_PLANE_COMMAND`
- `INFRA126_WAITINGROOM_ACQUIRE_COMMAND`
- `INFRA126_WAITINGROOM_RELEASE_COMMAND`

Each command reads one JSON document from stdin and returns zero only after successful completion.

## 4. Review and apply database migrations

Create a schema-only backup first:

```bash
pg_dump "$POSTGRES_URL" --schema=diskaudit --schema-only > /safe/path/diskaudit-before-infra126.sql
```

Apply in this order:

```bash
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/000_preflight.sql
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/001_infra126_core.sql
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/002_infra126_indexes_concurrently.sql
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/003_infra126_views_and_functions.sql
psql "$POSTGRES_URL" -v ON_ERROR_STOP=1 -f migrations/004_backfill_existing_hashes.sql
```

Run files 000 through 004 a second time. They must complete without schema errors. The concurrent index file must remain outside a transaction.

## 5. Validate schema state

```bash
. /etc/havnvard/infra126.env
.venv/bin/python scripts/validate_live.py
```

Expected minimums:

- 12 scheduled SLA rows: three hosts × A/B/C/E
- at least 20 registry rules
- all existing content hashes have `first_hash` and `first_hashed_at`
- zero rows where `verification_count > 0` but `last_verified_at IS NULL`

## 6. Prepare remote scratch

NAS:

```bash
ssh backup@nas-1.example.ts.net \
  'mkdir -p /share/CACHEDEV1_DATA/.diskaudit_scratch/infra126 && chmod 700 /share/CACHEDEV1_DATA/.diskaudit_scratch/infra126'
```

Agent-1:

```bash
ssh havnvard@agent-1.example.ts.net \
  'sudo install -d -o havnvard -g havnvard -m 0700 /var/lib/havnvard/infra126'
```

Never use NAS `/tmp`.

## 7. Run bounded acceptance batches

```bash
. /etc/havnvard/infra126.env
.venv/bin/havnvard-bitrot run --host server-1 --tier A --max-items 10
.venv/bin/havnvard-bitrot run --host nas-1 --tier A --max-items 10
.venv/bin/havnvard-bitrot run --host agent-1 --tier A --max-items 10
```

A capped run deliberately exits nonzero if more eligible files remain. That is not a silent success. Inspect the ten completed items and then run an uncapped acceptance run during an approved window.

## 8. Integrate UI, Grafana, and reports

- Register `web/infra126_blueprint.py` in the existing Flask application.
- Import or merge `grafana/infra126_dashboard.json`.
- Add `verification_report()` output to the daily HavnVard PRESI report.
- Add the monitor logic to the existing monitor process or install the supplied monitor timer.

## 9. Install units but keep them disabled

```bash
sudo install -m 0644 systemd/*.service systemd/*.timer /etc/systemd/system/
sudo systemctl daemon-reload
systemctl list-timers 'havnvard-infra126-*'
```

Manual services:

```bash
sudo systemctl start havnvard-infra126-a.service
journalctl -u havnvard-infra126-a.service -n 200 --no-pager
```

## 10. Enable after acceptance

```bash
sudo systemctl enable --now \
  havnvard-infra126-a.timer \
  havnvard-infra126-d.timer \
  havnvard-infra126-e.timer \
  havnvard-infra126-monitor.timer
```

Enable B and C only after A/E have run cleanly and the NAS maintenance calendar is confirmed.
