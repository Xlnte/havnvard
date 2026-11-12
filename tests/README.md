# Tests

Run: `cd /srv/diskaudit && .venv/bin/pytest tests/ -v` (about 5 minutes; the crosshost tests touch the live DB inside rolled-back
transactions, the NAS-dedup tests do not touch production at all).

| File | What it covers |
|---|---|
| `test_crosshost_verify.py` | `crosshost_verify.py` (candidate SQL, hash-loader idempotency, cross-host matching, INFRA-242 transport failure) **and the codebase-wide delete/move guard**: fails if any `shutil.move/rmtree`, `os.rename/replace`, `rm -rf` appears, or any `os.remove/os.unlink/rm -f` that is not on the reviewed `(file, line)` allowlist; plus `test_guard_rejects_new_unlisted_delete` so a green guard proves something. |
| `test_nas_dedup_core.py` | Pure functions of `nas_dedup_core.py` (no DB, no SSH): freshness truth table, scope pattern, batch planner, `verify_batch` completeness, keeper rule, progress note. |
| `test_hash_stat_batch.py` | The real `hash_stat_batch.sh` run under `sh` on files in `tmp_path` (stat fields, symlink/missing/non-regular rejection, `#DONE` trailer). |
| `test_nas_trigkey_dedup.py` | `nas_trigkey_dedup.py` end to end against a fake remote (`_fake_target.py`) and a throwaway schema: groups, hardlinks, freshness, scope, failure/retry/SIGTERM/exit codes, atomic publish, snapshot contract, export, migrations. |

## The `_test_` / throwaway-schema rules (HV-REQ-31)

* `conftest.py::nd_schema` creates a per-session schema `diskaudit_t_<hex>` from `LIKE diskaudit.<table> INCLUDING ALL` copies of the live
  table shapes (no data) plus the 1.4.0 migration (unchanged in 1.4.1) applied to it, and drops it at the end. Production gets no test rows and no DDL.
* `_dbguard.py::GuardedConn` rewrites every `diskaudit.` reference to that schema, so code under test physically cannot reach a production
  table through it, and ALSO refuses any write naming a real host (`nas-ts453a`, `trigkey`, `spark-20cf`, ...). Synthetic hosts are `_test_*`.
* `_fake_target.py::FakeTarget` runs the real `hash_stat_batch.sh` locally; no real SSH, no NAS.
* The crosshost tests keep their own convention (`_test_` hosts on the live schema, session-end sweep) and are unchanged.
