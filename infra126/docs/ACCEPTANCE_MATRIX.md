# Acceptance Matrix

Legend: **PASS-PACKAGE** means validated in the build sandbox. **LIVE-PENDING** requires the actual machine, database, external service, or production data.

| Requirement | Status | Evidence |
|---|---|---|
| Separate baseline from re-verification | PASS-PACKAGE | Schema and repository semantics |
| Frozen first hash | PASS-PACKAGE | `first_hash` never updated by verifier |
| Tier A selector | PASS-PACKAGE | Policy tests |
| Tier B selector | PASS-PACKAGE | Policy tests |
| Tier C without 31-90 gap | PASS-PACKAGE | Policy tests |
| Tier D stabilization | PASS-PACKAGE | Queue schema and selector |
| Tier E critical override | PASS-PACKAGE | Policy/classifier tests |
| Local SHA-256 | PASS-PACKAGE | Real temporary-file hashing test |
| NAS/agent-1 remote worker syntax | PASS-PACKAGE | Compilation and `sh -n` |
| NAS remote execution | LIVE-PENDING | Requires QNAP SSH |
| No NAS `/tmp` | PASS-PACKAGE | Config and runtime rejection |
| Metadata-before/after race detection | PASS-PACKAGE | Hashing implementation |
| Durable run/item state | PASS-PACKAGE | Migration and repository |
| Short transactions | PASS-PACKAGE | Hashing occurs outside repository transactions |
| `SKIP LOCKED` leasing | PASS-PACKAGE | Repository SQL |
| Resume expired leases | PASS-PACKAGE | Repository implementation |
| Live interrupted-run recovery | LIVE-PENDING | Requires process-kill acceptance test |
| Exact PID recovery | PASS-PACKAGE | Remote worker/recovery command |
| Mutable classifier | PASS-PACKAGE | Classifier tests |
| Immutable override | PASS-PACKAGE | Classifier tests |
| Two-copy conflict | PASS-PACKAGE | Multi-copy tests |
| Three-copy majority | PASS-PACKAGE | Multi-copy tests |
| No false “confirmed corruption” | PASS-PACKAGE | Decision wording and no auto-remediation |
| TG adapter | PASS-PACKAGE | Command adapter code |
| Actual TG delivery | LIVE-PENDING | Requires TG PRESI command |
| Plane adapter | PASS-PACKAGE | Command adapter code |
| Actual Plane ticket | LIVE-PENDING | Requires Plane command |
| Alert deduplication | PASS-PACKAGE | Fingerprint and event table |
| SLA reporting | PASS-PACKAGE | Views/reporting code |
| SLA query performance | LIVE-PENDING | Requires `EXPLAIN ANALYZE` on live data |
| Four Grafana panels | PASS-PACKAGE | Parsed dashboard JSON |
| Grafana rendering | LIVE-PENDING | Requires live Grafana |
| HavnVard verification UI | PASS-PACKAGE | Flask blueprint/templates |
| Existing tab integration | LIVE-PENDING | Existing UI source was not supplied |
| Restic integrity-state recording | PASS-PACKAGE | `record_restic_check.py` |
| Restic per-file hash evidence | PASS-PACKAGE | `restic_hash_copy.py` |
| Actual restic repositories | LIVE-PENDING | Requires credentials/repos |
| systemd A/B/C/D/E units | PASS-PACKAGE | Unit files and UTC timer tests |
| Actual timer run | LIVE-PENDING | Requires systemd deployment |
| No scanned-file delete/move/rename | PASS-PACKAGE | Static safety test |
| Full current repository regression suite | LIVE-PENDING | Actual HavnVard repository not supplied |
