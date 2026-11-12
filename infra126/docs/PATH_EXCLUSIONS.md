# INFRA-126 path-exclusion policy (INFRA-281)

## What it is

A configurable list of absolute path prefixes the verifier will **never enqueue**
for re-hashing. Introduced 2026-09-01 for `/home/olduser/` on `server-1`: the
deprecated olduser account home is mode `0750` and owned by `olduser`, the
verifier runs as `havnvard`, so every baseline under it hashed `unreadable`.
Those 34 items were 34 of the 38 errors on every Tier C run, which propagated
`completed_with_errors` -> `cli.py` exit 2 -> `havnvard-infra126-c.service`
failed. `ever_verified_files = 0` under that prefix, so excluding it costs no
coverage.

## Configuration

`INFRA126_EXCLUDE_PATH_PREFIXES`, read by `config.load_settings()`:

| Value | Meaning |
|---|---|
| unset | no exclusions (3.0.0; earlier versions shipped one site-specific default) |
| `server-1:/home/olduser/,/global/prefix/` | comma/newline list; `host:` optional (omitted = all hosts) |
| `[{"host":"agent-1","prefix":"/mnt/x/","reason":"PLANE-1"}]` | JSON array, carries a reason string |
| `""` (empty) | exclusions disabled entirely — deliberate operator choice |

Rejected loudly at load: relative prefixes, and `/`.

## An exclusion is never silent

Per `docs/STANDARDS/SILENT_FAILURE_STANDARD.md` a verifier that quietly ignores
part of the filesystem is a worse defect than the one it replaces. Every run
therefore reports each applicable prefix in three places, before any hashing:

1. **journal / log file** — `INFRA-126 PATH EXCLUDED BY POLICY run=... prefix=...
   due_excluded=N inventory_files=N baselined=N ever_verified=N reason=...`,
   at WARNING when the exclusion actually removed due candidates, INFO when it
   removed nothing.
2. **the run row** — `hash_verification_runs.config_json -> path_exclusions`,
   so the skip survives log rotation and stays auditable.
3. **the CLI summary JSON** — `excluded_by_policy` and `path_exclusions`.

`ever_verified_files` is the field that answers "did we lose coverage?".

## Excluded-by-policy is NOT failed-to-read

These are kept structurally apart, because conflating them is how a run reports
success over data it could not check:

| | Where it lands | Effect on run status |
|---|---|---|
| excluded by policy | `RunSummary.excluded_by_policy`, never becomes an item | none — cannot fail a run |
| failed to read | item state `unreadable`, counted in `finalize_run`'s error bucket | `completed_with_errors`, exit 2, unit failed |

`Repository` holds the policy so `enqueue_candidates` and
`count_due_excluding_run` can never disagree; if enqueue skipped a path but the
remaining-due count still counted it, every run would report
`completed_with_errors` forever.

## Proof (2026-09-01, live, server-1 Tier C)

| Run | exclusions | checked | read-failure errors | `excluded_by_policy` | run errors | status |
|---|---|---|---|---|---|---|
| `48bef6f6` | on (default) | 9 | 0 | 34 | 4 | completed_with_errors |
| `3399a813` | disabled (`=""`) | 43 | 34 (all `/home/olduser/`) | 0 | 38 | completed_with_errors |

The negative control is the proof that genuine read failures still fail a run.
The 4 residual errors in both runs are `stale_baseline` on churning system files
(`/var/log/journal/*.journal`, fwupd metadata) — a separate condition, tracked
in Plane, not a read failure and not affected by this change.
