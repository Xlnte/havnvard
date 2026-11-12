# Related Plane Items and Applications

This list reflects the open-item snapshot supplied with INFRA-126. It is not a live Plane query.

## Direct v1 dependencies

- INFRA-126: scheduled re-hashing
- INFRA-97: HavnVard whole-disk inventory parent
- INFRA-105: disk/file Grafana dashboard
- INFRA-98: progress checkpoints and hang detection
- INFRA-110: TechWatch scheduling collision
- INFRA-108: NAS crawl reliability
- INFRA-107: NAS/the server cadence mismatch
- MONITOR-16: full-stack success verification
- MONITOR-36: rotate exposed diskaudit-agent credential

## Backup and multi-copy dependencies

- INFRA-134, INFRA-96, INFRA-76, INFRA-109, INFRA-117
- INFRA-115, INFRA-116, INFRA-127, INFRA-124

## Deduplication, cleanup, and coverage

- INFRA-102, INFRA-136, INFRA-111, INFRA-112, INFRA-113
- INFRA-125, INFRA-128, INFRA-101

## Supporting/future work

- INFRA-119, INFRA-99, INFRA-114

## Directly relevant applications and infrastructure

- HavnVard / diskaudit
- PostgreSQL `havnvard.diskaudit`
- the server scanner and client agents
- NAS BusyBox crawler
- `crosshost_verify.py`
- `hash_batch.sh`
- `nas_trigkey_dedup.py`
- `backup_coverage.py`
- `monitor.py`
- HavnVard PRESI report
- HavnVard web UI
- systemd
- HELM WaitingRoom
- TechWatch
- restic
- QNAP RAID scrub and future snapshots
- the server, NAS, agent-1
- Grafana
- TG PRESI
- Plane
- THOTH
- FERJA, as a separate future remediation authority
