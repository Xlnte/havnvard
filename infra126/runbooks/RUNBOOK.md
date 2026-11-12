# INFRA-126 Operator Runbook

## STARTUP

```bash
cd /opt/havnvard/infra126
source .venv/bin/activate
set -a
source /etc/havnvard/infra126.env
set +a
```

## Health snapshot

```bash
havnvard-bitrot report
havnvard-bitrot monitor

psql "$POSTGRES_URL" -x -c "
SELECT host,tier,last_completed_at,last_successful_at,next_scheduled_at,
       files_total,files_on_time,files_pending,pct_on_time,last_completed_status
FROM diskaudit.v_infra126_sla_status
ORDER BY host,tier;"

psql "$POSTGRES_URL" -x -c "
SELECT run_id,host,tier,status,candidate_count,completed_count,matched_count,
       divergence_count,error_count,remaining_due_count,last_heartbeat_at,
       remote_pid,remote_work_dir,recovery_command,last_error
FROM diskaudit.hash_verification_runs
ORDER BY created_at DESC LIMIT 20;"

psql "$POSTGRES_URL" -x -c "
SELECT host,path,mutable_score,decision_state,operator_action,operator_verdict,
       last_seen_divergence_at,plane_ticket_id
FROM diskaudit.corruption_suspects
ORDER BY last_seen_divergence_at DESC LIMIT 50;"
```

## Manual tier runs

Bounded test:

```bash
havnvard-bitrot run --host server-1 --tier A --max-items 10
havnvard-bitrot run --host nas-1 --tier A --max-items 10
havnvard-bitrot run --host agent-1 --tier A --max-items 10
```

Full scheduled tiers:

```bash
python scripts/run_scheduled_tier.py --tier A
python scripts/run_scheduled_tier.py --tier B
python scripts/run_scheduled_tier.py --tier C
python scripts/run_scheduled_tier.py --tier D
python scripts/run_scheduled_tier.py --tier E
```

A capped run returns nonzero when eligible work remains. That is intentional and prevents a partial batch from being reported as successful SLA completion.

## Resume an interrupted run

Find the run:

```bash
psql "$POSTGRES_URL" -Atc "
SELECT run_id
FROM diskaudit.hash_verification_runs
WHERE status IN ('running','failed','blocked','completed_with_errors')
ORDER BY created_at DESC LIMIT 1;"
```

Resume by exact ID:

```bash
havnvard-bitrot run --host HOST --tier TIER --run-id RUN_UUID
```

Expired leases are returned to `pending` before work resumes.

## Remote orphan recovery

Never use `pkill -f`.

Read the exact command recorded for the run:

```bash
psql "$POSTGRES_URL" -Atc "
SELECT recovery_command
FROM diskaudit.hash_verification_runs
WHERE run_id='RUN_UUID';"
```

Inspect before executing:

```bash
ssh TARGET 'ps w | grep remote_hash_batch | grep -v grep'
ssh TARGET 'cat /PERSISTENT/SCRATCH/infra126/RUN_TOKEN/pid; cat /PERSISTENT/SCRATCH/infra126/RUN_TOKEN/token'
```

Execute only the recorded exact-PID/token recovery command.

## Synthetic stable-file acceptance

1. Create a dedicated test file in an approved test directory.
2. Ensure it is inventoried and baselined.
3. Run a bounded Tier A verification.
4. Confirm:

```sql
SELECT hash_status,last_verified_at,verification_count
FROM diskaudit.files
WHERE host='server-1' AND path='/approved/test/path';
```

Expected: `hash_status='verified'`, non-null `last_verified_at`, `verification_count >= 1`.

## Synthetic divergence acceptance

Do not alter a real critical file. Use a dedicated test file with a registry rule marking it immutable.

Expected results:

- one `hash_divergences` row;
- one `corruption_suspects` row;
- one TG event fingerprint;
- no baseline overwrite;
- no file remediation.

## Mutable baseline acceptance

Use a dedicated `.sqlite` test file:

1. Baseline it.
2. Modify it normally so mtime and size change.
3. Re-run verification.
4. Confirm `accepted_mutable_baseline` and one pending Tier D stabilization.
5. After the stabilization delay, run Tier D.
6. Confirm exact match changes the stabilization to `stable` and updates `last_verified_at`.

## Operator verdicts

Benign:

```sql
UPDATE diskaudit.corruption_suspects
SET operator_action='investigated',operator_verdict='benign',notes='EXPLANATION'
WHERE file_key='FILE_KEY';
```

Suspicious:

```sql
UPDATE diskaudit.corruption_suspects
SET operator_action='investigated',operator_verdict='suspicious',notes='EXPLANATION'
WHERE file_key='FILE_KEY';
```

Confirmed corruption:

```sql
UPDATE diskaudit.corruption_suspects
SET operator_action='investigated',operator_verdict='confirmed_corruption',notes='EVIDENCE'
WHERE file_key='FILE_KEY';
```

The monitor sends TG/Plane escalation. HavnVard does not restore or overwrite the file.

## Timer operations

```bash
systemctl list-timers 'havnvard-infra126-*'
systemctl status havnvard-infra126-a.timer
journalctl -u havnvard-infra126-a.service -n 200 --no-pager
journalctl -u havnvard-infra126-monitor.service -n 200 --no-pager
```

Disable all scheduling:

```bash
sudo systemctl disable --now \
  havnvard-infra126-a.timer \
  havnvard-infra126-b.timer \
  havnvard-infra126-c.timer \
  havnvard-infra126-d.timer \
  havnvard-infra126-e.timer \
  havnvard-infra126-monitor.timer
```

## NAS maintenance collision

Tier B is scheduled on day 7 and Tier C on day 8 of quarter months to avoid the known day-6 QNAP scrub. Before manual B/C runs, verify no scrub or heavy backup operation is active.

## Scratch retention

Remote scratch contains only INFRA-126 manifests, logs, results, PID, token, and heartbeat files. Review old run directories manually. Any cleanup command must target the exact INFRA-126 scratch directory and must never target scanned data.
