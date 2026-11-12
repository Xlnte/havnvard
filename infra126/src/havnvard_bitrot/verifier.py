from __future__ import annotations

import logging
import os
import socket
from pathlib import Path

from .alerts import AlertSink, fingerprint
from .classifier import classify_divergence
from .hashing import hash_file
from .multicopy import decide_copies
from .remote import RemoteBatchHasher
from .repository import Repository
from .transport import build_transport
from .types import FileCandidate, HashOutcome, RunSummary, Tier
from .waitingroom import WaitingRoomGate

logger = logging.getLogger(__name__)


class VerificationService:
    def __init__(
        self,
        repository: Repository,
        settings,
        alert_sink: AlertSink,
        plane_sink: AlertSink,
        waitingroom: WaitingRoomGate,
        helper_script: Path,
    ):
        self.repository = repository
        self.settings = settings
        self.alert_sink = alert_sink
        self.plane_sink = plane_sink
        self.waitingroom = waitingroom
        self.helper_script = helper_script
        self.worker_id = f"{socket.gethostname()}:{os.getpid()}"

    def _emit_once(
        self,
        sink: AlertSink,
        event_type: str,
        severity: str,
        host: str,
        path: str | None,
        discriminator: str,
        payload: dict,
        *,
        suppress_hours: int = 24,
    ) -> bool:
        key = fingerprint(event_type, host, path, discriminator)
        if not self.repository.reserve_alert(key, event_type, severity, host, path, payload, suppress_hours=suppress_hours):
            return False
        try:
            sink.send(event_type, severity, payload)
        except Exception as exc:
            self.repository.mark_alert_failed(key, str(exc))
            raise
        self.repository.mark_alert_sent(key)
        return True

    @staticmethod
    def _baseline_accept_allowed(classification, decision, candidate: FileCandidate, new_hash: str) -> bool:
        if not classification.auto_accept_baseline:
            return False
        if decision.state in {"two_copy_conflict", "three_way_split"}:
            return False
        if decision.state == "majority_odd_copy":
            return decision.authoritative_hash == new_hash and candidate.host not in decision.odd_sources
        return decision.state in {"insufficient_evidence", "all_agree"}

    def _process_result(self, tier: Tier, candidate: FileCandidate, result, patterns, summary: RunSummary) -> None:
        summary.checked += 1
        if result.status != HashOutcome.HASHED or not result.sha256:
            outcome = self.repository.record_result(candidate, result, tier, None, None)
            state = outcome["state"]
            if state == "missing":
                summary.missing += 1
            elif state == "changed_during_hash":
                summary.changed_during_hash += 1
            elif state == "stale_baseline":
                summary.stale_baseline += 1
            else:
                summary.errors += 1
            return

        if result.sha256 == candidate.baseline_hash:
            outcome = self.repository.record_result(candidate, result, tier, None, None)
            if outcome["state"] == "stale_baseline":
                summary.stale_baseline += 1
            else:
                summary.matched += 1
            return

        classification = classify_divergence(
            candidate.path,
            candidate.baseline_mtime_ns,
            result.mtime_ns,
            candidate.baseline_size,
            result.size,
            is_critical=candidate.is_critical,
            metadata_trusted=candidate.baseline_metadata_trusted,
            patterns=patterns,
            auto_accept_threshold=self.settings.auto_accept_mutable_score,
        )
        evidence = self.repository.copy_evidence(candidate, result.sha256)
        copy_decision = decide_copies(evidence)
        allow_accept = self._baseline_accept_allowed(classification, copy_decision, candidate, result.sha256)
        outcome = self.repository.record_result(
            candidate,
            result,
            tier,
            classification,
            copy_decision,
            allow_baseline_accept=allow_accept,
            stabilization_delay_hours=self.settings.stabilization_delay_hours,
        )
        if outcome["state"] == "stale_baseline":
            summary.stale_baseline += 1
            return
        summary.diverged += 1
        if outcome["state"] == "accepted_drift":
            summary.accepted_drift += 1

        divergence_id = outcome.get("divergence_id")
        payload = {
            "host": candidate.host,
            "path": candidate.path,
            "tier": tier.value,
            "old_hash": candidate.baseline_hash,
            "new_hash": result.sha256,
            "mutable_score": classification.score,
            "classifier_reason": classification.reason,
            "divergence_type": classification.divergence_type,
            "decision_state": copy_decision.state,
            "authoritative_hash": copy_decision.authoritative_hash,
            "odd_sources": list(copy_decision.odd_sources),
            "copy_reason": copy_decision.reason,
            "run_id": candidate.run_id,
            "divergence_id": divergence_id,
            "baseline_auto_accepted": outcome["state"] == "accepted_drift",
        }

        sent_tg = False
        sent_plane = False
        discriminator = f"{candidate.baseline_hash}:{result.sha256}"
        if candidate.is_critical or tier == Tier.E:
            sent_tg = self._emit_once(
                self.alert_sink,"critical_path_divergence","urgent",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=24,
            )
            sent_plane = self._emit_once(
                self.plane_sink,"critical_path_divergence","highest",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=168,
            )
        elif classification.score < 30:
            sent_tg = self._emit_once(
                self.alert_sink,"possible_corruption","warning",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=24,
            )

        if copy_decision.state == "two_copy_conflict":
            sent_tg = self._emit_once(
                self.alert_sink,"two_copy_conflict","warning",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=24,
            ) or sent_tg
        elif copy_decision.state == "majority_odd_copy" and candidate.host in copy_decision.odd_sources:
            sent_tg = self._emit_once(
                self.alert_sink,"majority_identifies_odd_copy","urgent",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=24,
            ) or sent_tg
            if classification.score < 30:
                sent_plane = self._emit_once(
                    self.plane_sink,"majority_identifies_odd_copy","highest",candidate.host,candidate.path,
                    discriminator,payload,suppress_hours=168,
                ) or sent_plane
        elif copy_decision.state == "three_way_split":
            sent_tg = self._emit_once(
                self.alert_sink,"three_way_split","urgent",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=24,
            ) or sent_tg
            sent_plane = self._emit_once(
                self.plane_sink,"three_way_split","highest",candidate.host,candidate.path,
                discriminator,payload,suppress_hours=168,
            ) or sent_plane

        if divergence_id and (sent_tg or sent_plane):
            self.repository.mark_divergence_escalated(divergence_id,tg=sent_tg,plane=sent_plane)

    def run(
        self,
        host: str,
        tier: Tier,
        *,
        run_id: str | None = None,
        max_items: int = 0,
        resume: bool = True,
    ) -> RunSummary:
        if host not in self.settings.hosts:
            raise ValueError(f"unknown host: {host}")
        existing = self.repository.find_resumable_run(host,tier) if resume and not run_id else None
        if run_id or existing:
            run_id = run_id or existing
            assert run_id is not None
            self.repository.create_run(host,tier,{"max_items": max_items},run_id=run_id)
            self.repository.resume_run(run_id)
        else:
            run_id = self.repository.create_run(host,tier,{"max_items": max_items})
        summary = RunSummary(run_id,host,tier.value)

        acquired = False
        try:
            acquired = self.waitingroom.acquire(
                run_id,host,tier.value,
                max_wait_seconds=self.settings.waitingroom_max_wait_seconds,
                retry_seconds=self.settings.waitingroom_retry_seconds,
                on_wait=lambda elapsed: self.repository.mark_run_blocked(
                    run_id,"HELM WaitingRoom is holding P3 verification",elapsed
                ),
            )
            if not acquired:
                reason = f"HELM WaitingRoom denied P3 admission for {self.settings.waitingroom_max_wait_seconds}s"
                self.repository.mark_run_blocked(run_id,reason,self.settings.waitingroom_max_wait_seconds)
                raise RuntimeError(reason)
            self.repository.resume_run(run_id)
            self.repository.reclaim_expired_leases(run_id)
            patterns = self.repository.mutable_patterns(host)
            host_config = self.settings.hosts[host]
            processed_this_invocation = 0

            # INFRA-281: report the path-exclusion policy BEFORE any work, and
            # persist it on the run row. An excluded path is a declared policy
            # skip, not a failure -- it is counted here and nowhere near the
            # error tally that decides run status.
            exclusion_report = self.repository.count_excluded_candidates(host, tier)
            if exclusion_report:
                summary.path_exclusions = exclusion_report
                summary.excluded_by_policy = sum(entry["due_excluded"] for entry in exclusion_report)
                self.repository.record_run_exclusions(run_id, exclusion_report)
                for entry in exclusion_report:
                    logger.log(
                        logging.WARNING if entry["due_excluded"] else logging.INFO,
                        "INFRA-126 PATH EXCLUDED BY POLICY run=%s host=%s tier=%s prefix=%s "
                        "due_excluded=%s inventory_files=%s baselined=%s ever_verified=%s reason=%s",
                        run_id, host, tier.value, entry["prefix"], entry["due_excluded"],
                        entry["inventory_files"], entry["baselined_files"],
                        entry["ever_verified_files"], entry["reason"],
                    )

            while True:
                remaining_capacity = max_items - processed_this_invocation if max_items else self.settings.enqueue_page_size
                if max_items and remaining_capacity <= 0:
                    break
                candidates = self.repository.claim_items(
                    run_id,self.worker_id,
                    min(self.settings.batch_size,remaining_capacity) if max_items else self.settings.batch_size,
                    self.settings.lease_seconds,
                )
                if not candidates:
                    page_size = min(self.settings.enqueue_page_size,remaining_capacity) if max_items else self.settings.enqueue_page_size
                    inserted = self.repository.enqueue_candidates(run_id,host,tier,page_size)
                    if inserted == 0:
                        break
                    candidates = self.repository.claim_items(
                        run_id,self.worker_id,
                        min(self.settings.batch_size,remaining_capacity) if max_items else self.settings.batch_size,
                        self.settings.lease_seconds,
                    )
                    if not candidates:
                        raise RuntimeError("candidates were enqueued but could not be leased")

                self.repository.mark_hashing([item.item_id for item in candidates],self.worker_id,self.settings.lease_seconds)
                self.repository.heartbeat(run_id)
                if host_config.mode == "local":
                    for candidate in candidates:
                        result = hash_file(
                            candidate.item_id,candidate.path,self.settings.hash_timeout_seconds,
                            progress_callback=lambda: self.repository.heartbeat(run_id),
                            progress_interval_seconds=self.settings.heartbeat_seconds,
                        )
                        self._process_result(tier,candidate,result,patterns,summary)
                        processed_this_invocation += 1
                        self.repository.heartbeat(run_id)
                else:
                    if not host_config.scratch_dir:
                        raise RuntimeError(f"remote host {host} is missing scratch_dir")
                    # sshpass hosts take their connection identity from the
                    # credentials file, so ssh_target is only required for pubkey.
                    if getattr(host_config,"auth","pubkey")=="pubkey" and not host_config.ssh_target:
                        raise RuntimeError(f"remote host {host} is missing ssh_target")
                    remote = RemoteBatchHasher(
                        self.helper_script,
                        self.settings.remote_batch_timeout_seconds,
                        self.settings.remote_poll_seconds,
                        self.settings.remote_heartbeat_stale_seconds,
                        transport=build_transport(host_config),
                    )
                    job = remote.launch(host_config.ssh_target or "",host_config.scratch_dir,run_id,candidates)
                    recovery = remote.recovery_command(job)
                    self.repository.heartbeat(run_id,remote_pid=job.pid,remote_work_dir=job.work_dir,recovery_command=recovery)
                    by_id = {item.item_id:item for item in candidates}
                    results = remote.wait(job,heartbeat_callback=lambda _: self.repository.heartbeat(run_id))
                    returned = set()
                    for result in results:
                        returned.add(result.item_id)
                        candidate = by_id.get(result.item_id)
                        if candidate is None:
                            logger.error("remote returned unknown item_id=%s",result.item_id)
                            summary.errors += 1
                            continue
                        self._process_result(tier,candidate,result,patterns,summary)
                        processed_this_invocation += 1
                        self.repository.heartbeat(run_id)
                    missing_results = set(by_id)-returned
                    if missing_results:
                        raise RuntimeError(f"remote batch omitted {len(missing_results)} leased item results")

                logger.info(
                    "INFRA-126 progress run=%s host=%s tier=%s checked=%s matched=%s divergences=%s errors=%s",
                    run_id,host,tier.value,summary.checked,summary.matched,summary.diverged,summary.errors,
                )

            final = self.repository.finalize_run(run_id,host,tier)
            summary.details.update(final)
            summary.details["excluded_by_policy"] = summary.excluded_by_policy
            summary.details["path_exclusions"] = summary.path_exclusions
            if final["status"] != "completed":
                self._emit_once(
                    self.alert_sink,"verification_run_incomplete","warning",host,None,run_id,
                    {"run_id":run_id,"host":host,"tier":tier.value,**final},suppress_hours=6,
                )
            return summary
        except Exception as exc:
            try:
                self.repository.finalize_run(run_id,host,tier,failed=True,error=str(exc))
            finally:
                self._emit_once(
                    self.alert_sink,"verification_run_failed","urgent",host,None,run_id,
                    {"run_id":run_id,"host":host,"tier":tier.value,"error":str(exc)},suppress_hours=1,
                )
            raise
        finally:
            if acquired:
                self.waitingroom.release(run_id,host,tier.value)
