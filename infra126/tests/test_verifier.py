from __future__ import annotations

import hashlib
import os
from pathlib import Path
from types import SimpleNamespace

from havnvard_bitrot.classifier import DEFAULT_PATTERNS
from havnvard_bitrot.types import CopyEvidence,FileCandidate,Tier
from havnvard_bitrot.verifier import VerificationService
from havnvard_bitrot.waitingroom import WaitingRoomGate


class Sink:
    def __init__(self): self.events=[]
    def send(self,event_type,severity,payload): self.events.append((event_type,severity,payload))


class FakeRepository:
    def __init__(self,candidate,other_evidence=None):
        self.candidate=candidate
        self.other_evidence=other_evidence or []
        self.enqueued=False
        self.claimed=False
        self.recorded=[]
        self.alerts=set()
        self.escalated=[]
        self.exclusion_report=[]
        self.recorded_exclusions=None
    def count_excluded_candidates(self,*_): return self.exclusion_report
    def record_run_exclusions(self,run_id,report): self.recorded_exclusions=(run_id,report)
    def find_resumable_run(self,*_): return None
    def create_run(self,*_,run_id=None,**__): return run_id or "run-1"
    def resume_run(self,*_): pass
    def mark_run_blocked(self,*_): pass
    def reclaim_expired_leases(self,*_): return 0
    def mutable_patterns(self,*_): return DEFAULT_PATTERNS
    def claim_items(self,*_):
        if self.enqueued and not self.claimed:
            self.claimed=True
            return [self.candidate]
        return []
    def enqueue_candidates(self,*_):
        if self.enqueued: return 0
        self.enqueued=True
        return 1
    def mark_hashing(self,*_): pass
    def heartbeat(self,*_,**__): pass
    def copy_evidence(self,candidate,observed_hash):
        return [CopyEvidence("live_host",candidate.host,observed_hash),*self.other_evidence]
    def record_result(self,candidate,result,tier,classification,decision,**kwargs):
        self.recorded.append((result,classification,decision,kwargs))
        if result.sha256 == candidate.baseline_hash: return {"state":"matched","alert":False}
        return {"state":"accepted_drift" if kwargs.get("allow_baseline_accept") else "diverged","alert":True,"divergence_id":1}
    def reserve_alert(self,key,*_,**__):
        if key in self.alerts: return False
        self.alerts.add(key); return True
    def mark_alert_sent(self,*_): pass
    def mark_alert_failed(self,*_): pass
    def mark_divergence_escalated(self,*args,**kwargs): self.escalated.append((args,kwargs))
    def finalize_run(self,*_,**__): return {"status":"completed","completed":1,"matched":1,"divergences":0,"errors":0,"pending":0,"remaining_due":0}


def settings(tmp_path):
    return SimpleNamespace(
        hosts={"server-1":SimpleNamespace(mode="local",ssh_target=None,scratch_dir=None)},
        batch_size=10,enqueue_page_size=10,lease_seconds=60,heartbeat_seconds=30,hash_timeout_seconds=30,
        remote_batch_timeout_seconds=30,remote_poll_seconds=1,remote_heartbeat_stale_seconds=5,auto_accept_mutable_score=90,
        stabilization_delay_hours=24,waitingroom_max_wait_seconds=1,waitingroom_retry_seconds=0,
    )


def candidate_for(path,baseline_hash,baseline_mtime,baseline_size):
    st=os.stat(path)
    return FileCandidate(1,"run-1","server-1",str(path),st.st_ino,baseline_hash,None,baseline_mtime,baseline_size,False,True)


def test_service_records_stable_match(tmp_path):
    path=tmp_path/"stable.txt"; path.write_text("stable")
    st=path.stat(); digest=hashlib.sha256(path.read_bytes()).hexdigest()
    repo=FakeRepository(candidate_for(path,digest,st.st_mtime_ns,st.st_size))
    tg=Sink(); plane=Sink()
    service=VerificationService(repo,settings(tmp_path),tg,plane,WaitingRoomGate(None,None),Path("unused"))
    summary=service.run("server-1",Tier.A)
    assert summary.matched==1
    assert not tg.events


def test_immutable_frozen_metadata_alerts(tmp_path):
    path=tmp_path/"hostname"; path.write_text("new-host")
    st=path.stat()
    candidate=FileCandidate(1,"run-1","server-1","/etc/hostname",st.st_ino,"0"*64,None,st.st_mtime_ns,st.st_size,False,True)
    repo=FakeRepository(candidate)
    tg=Sink(); plane=Sink()
    # Hash the temporary file while retaining the logical immutable path for classification.
    candidate=FileCandidate(candidate.item_id,candidate.run_id,candidate.host,str(path),candidate.inode,candidate.baseline_hash,candidate.baseline_hashed_at,candidate.baseline_mtime_ns,candidate.baseline_size,candidate.is_critical,candidate.baseline_metadata_trusted)
    repo.candidate=candidate
    # Add an immutable registry rule for this test path.
    from havnvard_bitrot.classifier import RegistryPattern
    repo.mutable_patterns=lambda *_:[RegistryPattern(str(path),10,"immutable test path",False,"immutable")]
    service=VerificationService(repo,settings(tmp_path),tg,plane,WaitingRoomGate(None,None),Path("unused"))
    summary=service.run("server-1",Tier.A)
    assert summary.diverged==1
    assert any(event[0]=="possible_corruption" for event in tg.events)


def test_explicit_mutable_change_can_advance_baseline_and_queue_stabilization(tmp_path):
    path=tmp_path/"app.sqlite"; path.write_text("new database bytes")
    st=path.stat()
    candidate=candidate_for(path,"0"*64,st.st_mtime_ns-2_000_000_000,st.st_size-1)
    repo=FakeRepository(candidate)
    tg=Sink(); plane=Sink()
    service=VerificationService(repo,settings(tmp_path),tg,plane,WaitingRoomGate(None,None),Path("unused"))
    summary=service.run("server-1",Tier.A)
    assert summary.accepted_drift==1
    _,classification,decision,kwargs=repo.recorded[0]
    assert classification.explicit_mutable_rule
    assert decision.state=="insufficient_evidence"
    assert kwargs["allow_baseline_accept"] is True


def test_majority_against_candidate_prevents_mutable_auto_accept(tmp_path):
    path=tmp_path/"app.sqlite"; path.write_text("new database bytes")
    st=path.stat(); old="a"*64
    candidate=candidate_for(path,old,st.st_mtime_ns-2_000_000_000,st.st_size-1)
    repo=FakeRepository(candidate,[CopyEvidence("live_host","nas",old),CopyEvidence("restic_snapshot","restic",old)])
    service=VerificationService(repo,settings(tmp_path),Sink(),Sink(),WaitingRoomGate(None,None),Path("unused"))
    service.run("server-1",Tier.A)
    assert repo.recorded[0][3]["allow_baseline_accept"] is False
