# Rollback

Rollback has two levels.

## Operational rollback

This is the preferred response to a bad deployment. It preserves all evidence.

```bash
sudo systemctl disable --now \
  havnvard-infra126-a.timer \
  havnvard-infra126-b.timer \
  havnvard-infra126-c.timer \
  havnvard-infra126-d.timer \
  havnvard-infra126-e.timer \
  havnvard-infra126-monitor.timer
```

Remove the Flask blueprint registration and Grafana dashboard if necessary. Do not drop tables while an investigation is open.

## Schema rollback

Only after exporting evidence:

```bash
pg_dump "$POSTGRES_URL" \
  --table=diskaudit.hash_verification_sla \
  --table=diskaudit.hash_verification_runs \
  --table=diskaudit.hash_verification_items \
  --table=diskaudit.hash_observations \
  --table=diskaudit.hash_divergences \
  --table=diskaudit.corruption_suspects \
  --table=diskaudit.hash_copy_links \
  --table=diskaudit.hash_copy_evidence \
  --table=diskaudit.hash_baseline_stabilizations \
  --table=diskaudit.infra126_alert_events \
  > /safe/path/infra126-evidence.sql
```

Then, in a reviewed maintenance window:

```sql
BEGIN;
DROP VIEW IF EXISTS diskaudit.v_sla_status;
DROP VIEW IF EXISTS diskaudit.v_infra126_sla_status;
DROP VIEW IF EXISTS diskaudit.v_infra126_verification_age;
DROP FUNCTION IF EXISTS diskaudit.infra126_refresh_sla(TEXT,CHAR);

DROP TABLE IF EXISTS diskaudit.hash_baseline_stabilizations;
DROP TABLE IF EXISTS diskaudit.infra126_alert_events;
DROP TABLE IF EXISTS diskaudit.backup_verification_state;
DROP TABLE IF EXISTS diskaudit.hash_copy_evidence;
DROP TABLE IF EXISTS diskaudit.hash_copy_links;
DROP TABLE IF EXISTS diskaudit.corruption_suspects;
DROP TABLE IF EXISTS diskaudit.hash_divergences;
DROP TABLE IF EXISTS diskaudit.infra126_critical_files;
DROP TABLE IF EXISTS diskaudit.infra126_critical_paths;
DROP TABLE IF EXISTS diskaudit.mutable_file_registry;
DROP TABLE IF EXISTS diskaudit.hash_observations;
DROP TABLE IF EXISTS diskaudit.hash_verification_items;
DROP TABLE IF EXISTS diskaudit.hash_verification_runs;
DROP TABLE IF EXISTS diskaudit.hash_verification_sla;
COMMIT;
```

Do **not** automatically drop the additive columns from `diskaudit.files`. They contain historical evidence and dropping them can lock the large table. Remove them only through a separate reviewed migration.
