from __future__ import annotations

import hashlib
import json
import socket
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterable

from .policy import candidate_predicate_sql, exclusion_predicate_sql
from .types import (
    Classification,
    CopyDecision,
    CopyEvidence,
    FileCandidate,
    HashOutcome,
    HashResult,
    ItemState,
    Tier,
)


def file_key(host: str, path: str, inode: int | None) -> str:
    raw = f"{host}\n{path}\n{'' if inode is None else inode}"
    encoded = raw.encode("utf-8", errors="surrogateescape")
    return hashlib.md5(encoded, usedforsecurity=False).hexdigest() + hashlib.md5(b"infra126:" + encoded, usedforsecurity=False).hexdigest()


class Repository:
    def __init__(self, postgres_url: str, exclusions=()):
        self.postgres_url = postgres_url
        # INFRA-281 path-exclusion policy. Held on the repository (rather than
        # threaded through every call site) so enqueue, the remaining-due count
        # that decides run status, and the exclusion report can never drift out
        # of agreement -- a run that skips a path but still counts it as "due"
        # would report completed_with_errors forever.
        self.exclusions = tuple(exclusions or ())

    def _exclusion_clause(self, host: str) -> tuple[str, list[str]]:
        """('AND NOT (...)', params) or ('', []) when nothing applies."""
        fragment, params = exclusion_predicate_sql(self.exclusions, host)
        return (f"AND ({fragment})" if fragment else ""), params

    @contextmanager
    def connect(self):
        import psycopg

        with psycopg.connect(self.postgres_url, autocommit=False) as conn:
            yield conn

    def create_run(self, host: str, tier: Tier, config: dict | None = None, run_id: str | None = None) -> str:
        run_id = run_id or str(uuid.uuid4())
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO diskaudit.hash_verification_runs
                    (run_id,host,tier,status,worker_id,config_json,started_at,last_heartbeat_at)
                VALUES (%s,%s,%s,'running',%s,%s::jsonb,now(),now())
                ON CONFLICT (run_id) DO UPDATE
                SET status='running', worker_id=EXCLUDED.worker_id,
                    started_at=COALESCE(diskaudit.hash_verification_runs.started_at,now()),
                    finished_at=NULL,last_error=NULL,last_heartbeat_at=now()
                """,
                (run_id, host, tier.value, socket.gethostname(), json.dumps(config or {})),
            )
            conn.commit()
        return run_id

    def find_resumable_run(self, host: str, tier: Tier) -> str | None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id::text
                FROM diskaudit.hash_verification_runs
                WHERE host=%s AND tier=%s AND status IN ('running','failed','blocked','completed_with_errors')
                  AND EXISTS (
                    SELECT 1 FROM diskaudit.hash_verification_items i
                    WHERE i.run_id=hash_verification_runs.run_id
                      AND i.state IN ('pending','leased','hashing')
                  )
                ORDER BY started_at DESC NULLS LAST,created_at DESC LIMIT 1
                """,
                (host, tier.value),
            )
            row = cur.fetchone()
            conn.rollback()
            return row[0] if row else None

    def resume_run(self, run_id: str) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET status='running',finished_at=NULL,last_error=NULL,last_heartbeat_at=now()
                WHERE run_id=%s::uuid
                """,
                (run_id,),
            )
            conn.commit()

    def mark_run_blocked(self, run_id: str, reason: str, blocked_seconds: int = 0) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET status='blocked',last_error=%s,last_heartbeat_at=now(),
                    blocked_seconds=GREATEST(blocked_seconds,%s)
                WHERE run_id=%s::uuid
                """,
                (reason, blocked_seconds, run_id),
            )
            conn.commit()

    def enqueue_candidates(self, run_id: str, host: str, tier: Tier, page_size: int) -> int:
        predicate = candidate_predicate_sql(tier)
        exclusion_clause, exclusion_params = self._exclusion_clause(host)
        sql = f"""
            INSERT INTO diskaudit.hash_verification_items
                (run_id,host,path,inode,file_key,baseline_hash,baseline_hashed_at,
                 baseline_mtime_ns,baseline_size,is_critical,baseline_metadata_trusted,state)
            SELECT
                %s::uuid,f.host,f.path,f.inode,
                (md5(f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')) || md5('infra126:' || f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,''))),
                f.content_sha256,COALESCE(f.hashed_at,f.first_hashed_at),
                f.hash_baseline_mtime_ns,
                f.hash_baseline_size,
                EXISTS (SELECT 1 FROM diskaudit.infra126_critical_files c WHERE c.host=f.host AND c.path=f.path),
                f.hash_baseline_metadata_trusted,
                'pending'
            FROM diskaudit.files f
            WHERE f.host=%s
              AND f.still_exists
              AND f.file_type='regular'
              AND f.content_sha256 IS NOT NULL
              AND f.first_hashed_at IS NOT NULL
              AND ({predicate})
              {exclusion_clause}
              AND NOT EXISTS (
                  SELECT 1 FROM diskaudit.hash_verification_items i
                  WHERE i.run_id=%s::uuid
                    AND i.file_key=(md5(f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')) || md5('infra126:' || f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')))
              )
            ORDER BY COALESCE(f.last_verified_at,COALESCE(f.hashed_at,f.first_hashed_at)) ASC,f.path
            LIMIT %s
            ON CONFLICT DO NOTHING
        """
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(sql, (run_id, host, *exclusion_params, run_id, page_size))
            inserted = cur.rowcount
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET candidate_count=(SELECT count(*) FROM diskaudit.hash_verification_items WHERE run_id=%s::uuid),
                    last_heartbeat_at=now()
                WHERE run_id=%s::uuid
                """,
                (run_id, run_id),
            )
            conn.commit()
            return inserted

    def count_due_excluding_run(self, run_id: str, host: str, tier: Tier) -> int:
        predicate = candidate_predicate_sql(tier)
        exclusion_clause, exclusion_params = self._exclusion_clause(host)
        sql = f"""
            SELECT count(*)
            FROM diskaudit.files f
            WHERE f.host=%s AND f.still_exists AND f.file_type='regular'
              AND f.content_sha256 IS NOT NULL AND f.first_hashed_at IS NOT NULL
              AND ({predicate})
              {exclusion_clause}
              AND NOT EXISTS (
                SELECT 1 FROM diskaudit.hash_verification_items i
                WHERE i.run_id=%s::uuid
                  AND i.file_key=(md5(f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')) || md5('infra126:' || f.host || E'\\n' || f.path || E'\\n' || COALESCE(f.inode::text,'')))
              )
        """
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(sql, (host, *exclusion_params, run_id))
            value = int(cur.fetchone()[0])
            conn.rollback()
            return value

    def count_excluded_candidates(self, host: str, tier: Tier) -> list[dict]:
        """Per-prefix visibility for every INFRA-281 exclusion on this host.

        An exclusion must never be a silent skip
        (docs/STANDARDS/SILENT_FAILURE_STANDARD.md). This reports, for each
        prefix, both how many baselines the exclusion actually removed from
        THIS tier's candidate set (`due_excluded`) and how many inventoried
        files sit under the prefix at all (`inventory_files`) -- so a reader
        can tell "we skipped nothing that was due" from "we skipped 40,000
        files that were due".
        """
        applicable = [item for item in self.exclusions if item.applies_to(host)]
        if not applicable:
            return []
        predicate = candidate_predicate_sql(tier)
        report: list[dict] = []
        with self.connect() as conn, conn.cursor() as cur:
            for exclusion in applicable:
                cur.execute(
                    f"""
                    SELECT
                      count(*) FILTER (
                        WHERE f.still_exists AND f.file_type='regular'
                          AND f.content_sha256 IS NOT NULL AND f.first_hashed_at IS NOT NULL
                          AND ({predicate})
                      ) AS due_excluded,
                      count(*) FILTER (WHERE f.still_exists) AS inventory_files,
                      count(*) FILTER (
                        WHERE f.still_exists AND f.content_sha256 IS NOT NULL
                      ) AS baselined_files,
                      count(*) FILTER (
                        WHERE f.still_exists AND f.last_verified_at IS NOT NULL
                      ) AS ever_verified_files
                    FROM diskaudit.files f
                    WHERE f.host=%s AND starts_with(f.path, %s)
                    """,
                    (host, exclusion.prefix),
                )
                due, inventory, baselined, verified = [int(value or 0) for value in cur.fetchone()]
                report.append({
                    "prefix": exclusion.prefix,
                    "host": exclusion.host or "*",
                    "reason": exclusion.reason,
                    "due_excluded": due,
                    "inventory_files": inventory,
                    "baselined_files": baselined,
                    "ever_verified_files": verified,
                })
            conn.rollback()
        return report

    def record_run_exclusions(self, run_id: str, report: list[dict]) -> None:
        """Persist the exclusion report onto the run row so the skip survives
        log rotation and is auditable long after the journal is gone."""
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET config_json = config_json || jsonb_build_object('path_exclusions', %s::jsonb)
                WHERE run_id=%s::uuid
                """,
                (json.dumps(report), run_id),
            )
            conn.commit()

    def reclaim_expired_leases(self, run_id: str) -> int:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_items
                SET state='pending',lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
                WHERE run_id=%s::uuid AND state IN ('leased','hashing') AND lease_expires_at < now()
                """,
                (run_id,),
            )
            count = cur.rowcount
            conn.commit()
            return count

    def claim_items(self, run_id: str, worker_id: str, batch_size: int, lease_seconds: int) -> list[FileCandidate]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                WITH picked AS (
                    SELECT item_id
                    FROM diskaudit.hash_verification_items
                    WHERE run_id=%s::uuid AND state='pending'
                    ORDER BY item_id
                    FOR UPDATE SKIP LOCKED
                    LIMIT %s
                )
                UPDATE diskaudit.hash_verification_items i
                SET state='leased',lease_owner=%s,
                    lease_expires_at=now()+make_interval(secs=>%s),
                    attempts=i.attempts+1,updated_at=now()
                FROM picked
                WHERE i.item_id=picked.item_id
                RETURNING i.item_id,i.run_id::text,i.host,i.path,i.inode,
                          i.baseline_hash,i.baseline_hashed_at,i.baseline_mtime_ns,
                          i.baseline_size,i.is_critical,i.baseline_metadata_trusted
                """,
                (run_id, batch_size, worker_id, lease_seconds),
            )
            rows = cur.fetchall()
            conn.commit()
        return [FileCandidate(*row) for row in rows]

    def mark_hashing(self, item_ids: Iterable[int], worker_id: str, lease_seconds: int) -> None:
        ids = list(item_ids)
        if not ids:
            return
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_items
                SET state='hashing',lease_owner=%s,
                    lease_expires_at=now()+make_interval(secs=>%s),updated_at=now()
                WHERE item_id=ANY(%s)
                """,
                (worker_id, lease_seconds, ids),
            )
            conn.commit()

    def heartbeat(self, run_id: str, *, remote_pid: int | None = None, remote_work_dir: str | None = None, recovery_command: str | None = None) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET last_heartbeat_at=now(),remote_pid=COALESCE(%s,remote_pid),
                    remote_work_dir=COALESCE(%s,remote_work_dir),
                    recovery_command=COALESCE(%s,recovery_command)
                WHERE run_id=%s::uuid
                """,
                (remote_pid, remote_work_dir, recovery_command, run_id),
            )
            conn.commit()

    def mutable_patterns(self, host: str):
        from .classifier import RegistryPattern

        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT path_pattern,score,reason,is_regex,pattern_kind
                FROM diskaudit.mutable_file_registry
                WHERE host='*' OR host=%s
                ORDER BY priority ASC,CASE WHEN host=%s THEN 0 ELSE 1 END,registry_id ASC
                """,
                (host,host),
            )
            rows = cur.fetchall()
            conn.rollback()
        return [RegistryPattern(*row) for row in rows]

    def copy_evidence(self, candidate: FileCandidate, observed_hash: str, observed_at: datetime | None = None) -> list[CopyEvidence]:
        observed_at = observed_at or datetime.now(timezone.utc)
        key = file_key(candidate.host, candidate.path, candidate.inode)
        evidence: list[CopyEvidence] = [CopyEvidence("live_host", candidate.host, observed_hash, observed_at)]
        with self.connect() as conn, conn.cursor() as cur:
            # Never assume equal paths on different hosts are copies. Only explicit
            # logical-file links and independently registered evidence can vote.
            cur.execute(
                """
                SELECT 'live_host',l.independent_source_id,f.content_sha256,f.last_verified_at
                FROM diskaudit.hash_copy_links l
                JOIN diskaudit.files f ON f.host=l.source_host AND f.path=l.source_path
                WHERE l.logical_file_key=%s AND l.source_kind='live_host'
                  AND f.still_exists AND f.file_type='regular' AND f.content_sha256 IS NOT NULL
                  AND f.last_verified_at IS NOT NULL
                  AND f.last_verified_at >= COALESCE(f.hashed_at,f.first_hashed_at)
                UNION ALL
                SELECT e.source_kind,e.independent_source_id,e.sha256,e.captured_at
                FROM (
                  SELECT DISTINCT ON (independent_source_id)
                         source_kind,independent_source_id,sha256,captured_at
                  FROM diskaudit.hash_copy_evidence
                  WHERE logical_file_key=%s AND verification_state='verified'
                  ORDER BY independent_source_id,captured_at DESC NULLS LAST,created_at DESC
                ) e
                """,
                (key, key),
            )
            evidence.extend(CopyEvidence(*row) for row in cur.fetchall())
            conn.rollback()
        # Keep one latest vote per independent source.
        latest: dict[str, CopyEvidence] = {}
        for item in evidence:
            current = latest.get(item.source_id)
            if current is None or (item.captured_at or datetime.min.replace(tzinfo=timezone.utc)) > (current.captured_at or datetime.min.replace(tzinfo=timezone.utc)):
                latest[item.source_id] = item
        return list(latest.values())

    @staticmethod
    def _state_for_hash_failure(outcome: HashOutcome) -> ItemState:
        return {
            HashOutcome.UNREADABLE: ItemState.UNREADABLE,
            HashOutcome.CHANGED_DURING_HASH: ItemState.CHANGED_DURING_HASH,
            HashOutcome.MISSING: ItemState.MISSING,
            HashOutcome.FAILED: ItemState.FAILED,
            HashOutcome.SKIPPED: ItemState.SKIPPED,
        }[outcome]

    def _insert_observation(self, cur, candidate: FileCandidate, result: HashResult, result_state: str) -> None:
        cur.execute(
            """
            INSERT INTO diskaudit.hash_observations
                (run_id,item_id,host,path,file_key,baseline_hash,observed_hash,result_state,
                 observed_size,observed_mtime_ns,observed_inode,observed_at)
            VALUES (%s::uuid,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,now())
            ON CONFLICT(run_id,item_id) DO UPDATE
            SET observed_hash=EXCLUDED.observed_hash,result_state=EXCLUDED.result_state,
                observed_size=EXCLUDED.observed_size,observed_mtime_ns=EXCLUDED.observed_mtime_ns,
                observed_inode=EXCLUDED.observed_inode,observed_at=EXCLUDED.observed_at
            """,
            (
                candidate.run_id,candidate.item_id,candidate.host,candidate.path,
                file_key(candidate.host,candidate.path,candidate.inode),candidate.baseline_hash,
                result.sha256,result_state,result.size,result.mtime_ns,result.inode,
            ),
        )

    def record_result(
        self,
        candidate: FileCandidate,
        result: HashResult,
        tier: Tier,
        classification: Classification | None,
        copy_decision: CopyDecision | None,
        *,
        allow_baseline_accept: bool = False,
        stabilization_delay_hours: int = 24,
    ) -> dict:
        key = file_key(candidate.host, candidate.path, candidate.inode)
        if result.status != HashOutcome.HASHED or not result.sha256:
            final_state = self._state_for_hash_failure(result.status).value
            with self.connect() as conn, conn.cursor() as cur:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_verification_items
                    SET state=%s,observed_hash=%s,observed_size=%s,observed_mtime_ns=%s,
                        observed_inode=%s,duration_ms=%s,error_text=%s,
                        lease_owner=NULL,lease_expires_at=NULL,completed_at=now(),updated_at=now()
                    WHERE item_id=%s
                    """,
                    (final_state,result.sha256,result.size,result.mtime_ns,result.inode,result.duration_ms,result.error,candidate.item_id),
                )
                cur.execute(
                    """
                    UPDATE diskaudit.files
                    SET last_hash_attempt_at=now(),hash_status=%s,hash_error=%s
                    WHERE host=%s AND path=%s AND inode IS NOT DISTINCT FROM %s
                    """,
                    (final_state,result.error,candidate.host,candidate.path,candidate.inode),
                )
                self._insert_observation(cur,candidate,result,final_state)
                conn.commit()
            return {"state": final_state, "alert": False}

        with self.connect() as conn, conn.cursor() as cur:
            if candidate.inode is not None and result.inode is not None and result.inode != candidate.inode:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_verification_items
                    SET state='stale_baseline',observed_hash=%s,observed_size=%s,observed_mtime_ns=%s,
                        observed_inode=%s,duration_ms=%s,error_text='inode changed since inventory baseline',
                        lease_owner=NULL,lease_expires_at=NULL,completed_at=now(),updated_at=now()
                    WHERE item_id=%s
                    """,
                    (result.sha256,result.size,result.mtime_ns,result.inode,result.duration_ms,candidate.item_id),
                )
                self._insert_observation(cur,candidate,result,"stale_baseline")
                conn.commit()
                return {"state":"stale_baseline","alert":False}
            cur.execute(
                """
                SELECT content_sha256,COALESCE(hashed_at,first_hashed_at)
                FROM diskaudit.files
                WHERE host=%s AND path=%s AND inode IS NOT DISTINCT FROM %s
                FOR UPDATE
                """,
                (candidate.host,candidate.path,candidate.inode),
            )
            current = cur.fetchone()
            if not current or current[0] != candidate.baseline_hash or current[1] != candidate.baseline_hashed_at:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_verification_items
                    SET state='stale_baseline',observed_hash=%s,observed_size=%s,observed_mtime_ns=%s,
                        observed_inode=%s,duration_ms=%s,error_text='database baseline changed during verification',
                        lease_owner=NULL,lease_expires_at=NULL,completed_at=now(),updated_at=now()
                    WHERE item_id=%s
                    """,
                    (result.sha256,result.size,result.mtime_ns,result.inode,result.duration_ms,candidate.item_id),
                )
                self._insert_observation(cur,candidate,result,"stale_baseline")
                conn.commit()
                return {"state": "stale_baseline", "alert": False}

            if result.sha256 == candidate.baseline_hash:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_verification_items
                    SET state='matched',observed_hash=%s,observed_size=%s,observed_mtime_ns=%s,
                        observed_inode=%s,duration_ms=%s,completed_at=now(),
                        lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
                    WHERE item_id=%s
                    """,
                    (result.sha256,result.size,result.mtime_ns,result.inode,result.duration_ms,candidate.item_id),
                )
                cur.execute(
                    """
                    UPDATE diskaudit.files
                    SET last_hash_attempt_at=now(),last_verified_at=now(),
                        verification_count=COALESCE(verification_count,0)+1,
                        hash_baseline_mtime_ns=%s,hash_baseline_size=%s,
                        hash_baseline_inode=%s,hash_baseline_metadata_trusted=true,
                        hash_status='verified',hash_error=NULL
                    WHERE host=%s AND path=%s AND inode IS NOT DISTINCT FROM %s
                    """,
                    (result.mtime_ns,result.size,result.inode,candidate.host,candidate.path,candidate.inode),
                )
                self._insert_observation(cur,candidate,result,"matched")
                if tier == Tier.D:
                    cur.execute(
                        """
                        UPDATE diskaudit.hash_baseline_stabilizations
                        SET state='stable',completed_at=now(),last_error=NULL
                        WHERE file_key=%s AND accepted_hash=%s AND state IN ('pending','running')
                        """,
                        (key,candidate.baseline_hash),
                    )
                conn.commit()
                return {"state": "matched", "alert": False}

            if classification is None or copy_decision is None:
                raise ValueError("classification and copy_decision are required for a hash divergence")

            effective_accept = bool(allow_baseline_accept and classification.auto_accept_baseline)
            final_state = "accepted_drift" if effective_accept else "diverged"
            cur.execute(
                """
                INSERT INTO diskaudit.hash_divergences
                    (run_id,item_id,tier,host,path,inode,file_key,old_hash,new_hash,old_hashed_at,new_hashed_at,
                     mtime_old,mtime_new,size_old,size_new,divergence_type,mutable_score,
                     classifier_reason,decision_state,authoritative_hash,odd_sources)
                VALUES (%s::uuid,%s,%s,%s,%s,%s,%s,%s,%s,%s,now(),%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(run_id,item_id) DO UPDATE
                SET last_seen_divergence_at=now()
                RETURNING divergence_id
                """,
                (
                    candidate.run_id,candidate.item_id,tier.value,candidate.host,candidate.path,candidate.inode,key,
                    candidate.baseline_hash,result.sha256,candidate.baseline_hashed_at,
                    candidate.baseline_mtime_ns,result.mtime_ns,candidate.baseline_size,result.size,
                    classification.divergence_type,classification.score,classification.reason,
                    copy_decision.state,copy_decision.authoritative_hash,list(copy_decision.odd_sources),
                ),
            )
            divergence_id = cur.fetchone()[0]
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_items
                SET state=%s,observed_hash=%s,observed_size=%s,observed_mtime_ns=%s,
                    observed_inode=%s,duration_ms=%s,completed_at=now(),
                    lease_owner=NULL,lease_expires_at=NULL,updated_at=now()
                WHERE item_id=%s
                """,
                (final_state,result.sha256,result.size,result.mtime_ns,result.inode,result.duration_ms,candidate.item_id),
            )
            if effective_accept:
                cur.execute(
                    """
                    UPDATE diskaudit.files
                    SET content_sha256=%s,hashed_at=now(),last_hash_attempt_at=now(),
                        hash_baseline_mtime_ns=%s,hash_baseline_size=%s,hash_baseline_inode=%s,
                        hash_baseline_metadata_trusted=true,last_baseline_accepted_at=now(),
                        baseline_revision_count=COALESCE(baseline_revision_count,0)+1,
                        hash_divergence_count=COALESCE(hash_divergence_count,0)+1,
                        hash_status='accepted_mutable_baseline',hash_error=NULL
                    WHERE host=%s AND path=%s AND inode IS NOT DISTINCT FROM %s
                    """,
                    (result.sha256,result.mtime_ns,result.size,result.inode,candidate.host,candidate.path,candidate.inode),
                )
                cur.execute(
                    """
                    INSERT INTO diskaudit.hash_baseline_stabilizations
                        (file_key,host,path,inode,accepted_hash,accepted_at,due_at)
                    VALUES (%s,%s,%s,%s,%s,now(),now()+make_interval(hours=>%s))
                    ON CONFLICT(file_key,accepted_hash) DO UPDATE
                    SET due_at=EXCLUDED.due_at,state='pending',last_error=NULL,completed_at=NULL
                    """,
                    (key,candidate.host,candidate.path,candidate.inode,result.sha256,stabilization_delay_hours),
                )
            else:
                cur.execute(
                    """
                    UPDATE diskaudit.files
                    SET last_hash_attempt_at=now(),
                        hash_divergence_count=COALESCE(hash_divergence_count,0)+1,
                        hash_status='diverged',hash_error=NULL
                    WHERE host=%s AND path=%s AND inode IS NOT DISTINCT FROM %s
                    """,
                    (candidate.host,candidate.path,candidate.inode),
                )
                cur.execute(
                    """
                    INSERT INTO diskaudit.corruption_suspects
                        (file_key,host,path,inode,first_divergence_at,last_seen_divergence_at,
                         mutable_score,decision_state,latest_divergence_id)
                    VALUES (%s,%s,%s,%s,now(),now(),%s,%s,%s)
                    ON CONFLICT(file_key) DO UPDATE
                    SET last_seen_divergence_at=now(),mutable_score=EXCLUDED.mutable_score,
                        decision_state=EXCLUDED.decision_state,latest_divergence_id=EXCLUDED.latest_divergence_id,
                        host=EXCLUDED.host,path=EXCLUDED.path,inode=EXCLUDED.inode,
                        operator_action=NULL,operator_verdict=NULL,escalated_to_plane=false,
                        plane_ticket_id=NULL,notes=NULL
                    """,
                    (key,candidate.host,candidate.path,candidate.inode,classification.score,copy_decision.state,divergence_id),
                )
            self._insert_observation(cur,candidate,result,final_state)
            if tier == Tier.D:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_baseline_stabilizations
                    SET state='diverged',completed_at=now(),last_error='accepted baseline diverged during stabilization'
                    WHERE file_key=%s AND accepted_hash=%s AND state IN ('pending','running')
                    """,
                    (key,candidate.baseline_hash),
                )
            conn.commit()
        return {
            "state": final_state,
            "alert": classification.score < 30 or copy_decision.state in {"two_copy_conflict","majority_odd_copy","three_way_split"},
            "divergence_id": divergence_id,
        }

    def reserve_alert(self, fingerprint_value: str, event_type: str, severity: str, host: str, path: str | None, payload: dict, suppress_hours: int = 24) -> bool:
        """Atomically lease one alert delivery.

        The lease prevents two verifier/monitor processes from sending the same
        fingerprint concurrently. A failed sender releases the lease so the next
        monitor cycle can retry.
        """
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO diskaudit.infra126_alert_events
                    (fingerprint,event_type,severity,host,path,payload,first_seen_at,last_seen_at,
                     send_count,delivery_state,delivery_lease_until)
                VALUES (%s,%s,%s,%s,%s,%s::jsonb,now(),now(),0,'sending',now()+interval '5 minutes')
                ON CONFLICT(fingerprint) DO UPDATE
                SET last_seen_at=now(),payload=EXCLUDED.payload,severity=EXCLUDED.severity,
                    delivery_state='sending',delivery_lease_until=now()+interval '5 minutes',last_error=NULL
                WHERE (diskaudit.infra126_alert_events.last_sent_at IS NULL
                       OR diskaudit.infra126_alert_events.last_sent_at < now()-make_interval(hours=>%s))
                  AND (diskaudit.infra126_alert_events.delivery_lease_until IS NULL
                       OR diskaudit.infra126_alert_events.delivery_lease_until < now())
                RETURNING fingerprint
                """,
                # INFRA-140 (20260828): payload dicts can carry datetime values (e.g. SLA
                # timestamps) -- default=str matches the convention already used by
                # cli.py/validate_live.py/infra126_blueprint.py's own json.dumps calls.
                (fingerprint_value,event_type,severity,host,path,json.dumps(payload,default=str),suppress_hours),
            )
            row = cur.fetchone()
            conn.commit()
            return row is not None

    def mark_alert_sent(self, fingerprint_value: str) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.infra126_alert_events
                SET last_sent_at=now(),send_count=send_count+1,delivery_state='sent',
                    delivery_lease_until=NULL,last_error=NULL
                WHERE fingerprint=%s
                """,
                (fingerprint_value,),
            )
            conn.commit()

    def mark_alert_failed(self, fingerprint_value: str, error: str) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.infra126_alert_events
                SET delivery_state='failed',delivery_lease_until=NULL,last_error=%s,last_seen_at=now()
                WHERE fingerprint=%s
                """,
                (error[:4000],fingerprint_value),
            )
            conn.commit()

    def mark_divergence_escalated(self, divergence_id: int, *, tg: bool = False, plane: bool = False) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.hash_divergences
                SET escalated_to_tg=CASE WHEN %s THEN true ELSE escalated_to_tg END,
                    escalated_to_plane=CASE WHEN %s THEN true ELSE escalated_to_plane END
                WHERE divergence_id=%s
                """,
                (tg,plane,divergence_id),
            )
            conn.commit()

    def confirmed_corruption_pending_escalation(self) -> list[dict]:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT s.suspect_id,s.host,s.path,s.mutable_score,s.operator_verdict,
                       s.latest_divergence_id,d.old_hash,d.new_hash,d.decision_state
                FROM diskaudit.corruption_suspects s
                JOIN diskaudit.hash_divergences d ON d.divergence_id=s.latest_divergence_id
                WHERE s.operator_verdict='confirmed_corruption' AND NOT s.escalated_to_plane
                """
            )
            columns = ["suspect_id","host","path","mutable_score","operator_verdict","divergence_id","old_hash","new_hash","decision_state"]
            rows = [dict(zip(columns,row)) for row in cur.fetchall()]
            conn.rollback()
            return rows

    def mark_suspect_plane_escalated(self, suspect_id: int, ticket_id: str | None = None) -> None:
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE diskaudit.corruption_suspects
                SET escalated_to_plane=true,plane_ticket_id=COALESCE(%s,plane_ticket_id)
                WHERE suspect_id=%s
                """,
                (ticket_id,suspect_id),
            )
            conn.commit()

    def finalize_run(self, run_id: str, host: str, tier: Tier, *, failed: bool = False, error: str | None = None) -> dict:
        remaining_due = 0 if failed or tier == Tier.D else self.count_due_excluding_run(run_id,host,tier)
        with self.connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                  count(*) FILTER (WHERE state IN ('matched','diverged','accepted_drift','unreadable','missing','failed','changed_during_hash','stale_baseline','skipped')),
                  count(*) FILTER (WHERE state='matched'),
                  count(*) FILTER (WHERE state IN ('diverged','accepted_drift')),
                  count(*) FILTER (WHERE state IN ('unreadable','missing','failed','changed_during_hash','stale_baseline','skipped')),
                  count(*) FILTER (WHERE state IN ('pending','leased','hashing'))
                FROM diskaudit.hash_verification_items WHERE run_id=%s::uuid
                """,
                (run_id,),
            )
            completed,matched,divergences,errors,pending = [int(value or 0) for value in cur.fetchone()]
            if failed:
                status = "failed"
            elif errors or pending or remaining_due:
                status = "completed_with_errors"
            else:
                status = "completed"
            cur.execute(
                """
                UPDATE diskaudit.hash_verification_runs
                SET status=%s,finished_at=now(),last_heartbeat_at=now(),last_error=%s,
                    completed_count=%s,matched_count=%s,divergence_count=%s,error_count=%s,
                    remaining_due_count=%s
                WHERE run_id=%s::uuid
                """,
                (status,error,completed,matched,divergences,errors,remaining_due,run_id),
            )
            if tier != Tier.D:
                cur.execute(
                    """
                    UPDATE diskaudit.hash_verification_sla s
                    SET last_completed_at=now(),last_completed_status=%s,last_run_id=%s::uuid,
                        last_successful_at=CASE WHEN %s='completed' THEN now() ELSE last_successful_at END,
                        last_successful_run_id=CASE WHEN %s='completed' THEN %s::uuid ELSE last_successful_run_id END,
                        next_scheduled_at=diskaudit.infra126_next_scheduled(s.tier,now()),
                        updated_at=now()
                    WHERE s.host=%s AND s.tier=%s
                    """,
                    (status,run_id,status,status,run_id,host,tier.value),
                )
                cur.execute("SELECT diskaudit.infra126_refresh_sla(%s,%s)",(host,tier.value))
            conn.commit()
        return {
            "status": status,
            "completed": completed,
            "matched": matched,
            "divergences": divergences,
            "errors": errors,
            "pending": pending,
            "remaining_due": remaining_due,
        }
