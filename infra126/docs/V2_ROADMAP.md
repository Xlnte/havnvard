# v+2 Roadmap

## FERJA remediation

FERJA must remain a separate, delete/overwrite-authorized component. HavnVard emits evidence and a recommendation only.

Required approval record:

- operator identity;
- exact host/path;
- selected source and snapshot;
- expected source hash;
- divergent destination hash;
- expiration time;
- one-time approval token.

FERJA sequence:

1. Re-read source and destination metadata.
2. Hash the source again.
3. Refuse if evidence changed.
4. Copy to a new temporary destination path.
5. Hash the temporary copy.
6. Atomically replace only after explicit approval and matching hash.
7. Preserve rollback material.
8. Re-hash final destination.
9. Write an immutable audit record.

No FERJA restore code is included in this HavnVard package.

## Predictive drive-failure correlation

SMART and RAID telemetry can be correlated with divergence counts, but the roadmap must not promise exact file-to-physical-drive mapping on RAID5 without validating the QNAP storage stack. Logical blocks are striped across multiple disks and filesystem extents can move.

Practical v+2 scope:

- collect per-drive SMART trends;
- collect RAID scrub errors and repairs;
- correlate divergence spikes by NAS volume/share and time window;
- raise a drive-health investigation when both hardware errors and file divergences increase;
- avoid claiming a precise failure date or guaranteed two-week warning.

## Continuous verification daemon

The daemon can reuse the same run/item tables and verifier. Add:

- token-bucket read throttling;
- P3 WaitingRoom admission and periodic yield/reacquire;
- host/share fairness;
- priority boost for critical, never-verified, and long-overdue files;
- rolling throughput and coverage metrics;
- clean shutdown that releases leases.

Scheduled tiers remain as SLA backstops.

## Multi-device coverage

Do not give mobile and desktop agents direct PostgreSQL credentials. Use an authenticated ingestion API with device-scoped tokens, encryption in transit, replay protection, and server-side validation.

Platform constraints:

- Windows: VSS/USN journal awareness, ACL handling, long paths.
- iOS: sandbox limits, background execution limits, battery/Wi-Fi gates.
- Android: scoped storage and charging/Wi-Fi gates.

This is a separate product effort, not an INFRA-126 v1 dependency.
