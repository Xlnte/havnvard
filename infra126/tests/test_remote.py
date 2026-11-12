from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from havnvard_bitrot.remote import RemoteBatchHasher,RemoteJob
from havnvard_bitrot.transport import PubkeySshTransport
from havnvard_bitrot.types import FileCandidate,HashOutcome


def test_remote_wait_terminates_stale_heartbeat(monkeypatch):
    hasher=RemoteBatchHasher(Path("helper"),timeout_seconds=100,poll_seconds=0,heartbeat_stale_seconds=5)
    job=RemoteJob("host","/scratch/run",123,"/scratch/run/results","/scratch/run/heartbeat","token")
    monkeypatch.setattr(hasher,"_probe",lambda _:("running",100))
    terminated=[]
    monkeypatch.setattr(hasher,"terminate",lambda value: terminated.append(value.pid))
    monkeypatch.setattr("havnvard_bitrot.remote.time.sleep",lambda _: None)
    ticks=iter([0.0,0.0,0.0,1.0,1.0,6.1,6.1])
    monkeypatch.setattr("havnvard_bitrot.remote.time.monotonic",lambda: next(ticks))
    with pytest.raises(TimeoutError,match="heartbeat stale"):
        hasher.wait(job)
    assert terminated==[123]


class FakeTransport:
    """Records every transport call so tests can assert routing and ordering."""

    def __init__(self,target="backup@nas-1.example",launch_stdout="4242\n"):
        self.target=target
        self.calls=[]
        self.launch_stdout=launch_stdout
        self.result_payload='{"item_id":1,"path":"/data/file","status":"hashed","sha256":"deadbeef","size":10,"mtime_ns":5,"inode":7,"duration_ms":3}\n'

    def ssh(self,remote_cmd,*,timeout,check=True,background=False):
        self.calls.append(("ssh",remote_cmd,{"timeout":timeout,"check":check,"background":background}))
        return SimpleNamespace(stdout=self.launch_stdout if background else "",stderr="",returncode=0)

    def scp_put(self,local_path,remote_path,*,timeout):
        self.calls.append(("scp_put",str(local_path),{"remote_path":remote_path,"timeout":timeout}))
        return SimpleNamespace(stdout="",stderr="",returncode=0)

    def scp_get(self,remote_path,local_path,*,timeout):
        self.calls.append(("scp_get",remote_path,{"local_path":str(local_path),"timeout":timeout}))
        Path(local_path).write_text(self.result_payload,encoding="utf-8")
        return SimpleNamespace(stdout="",stderr="",returncode=0)

    def recovery_prefix(self):
        return f"sshpass -f <(...) ssh -o PubkeyAuthentication=no {self.target}"


def _candidates():
    return [FileCandidate(1,"run-1","nas-1","/data/file",7,"0"*64,None,5,10,False,True)]


def _hasher(transport,tmp_path):
    helper=tmp_path/"remote_hash_batch.sh"
    helper.write_text("#!/bin/sh\n",encoding="utf-8")
    return RemoteBatchHasher(helper,timeout_seconds=100,poll_seconds=0,heartbeat_stale_seconds=5,transport=transport)


def test_launch_routes_every_step_through_transport(tmp_path):
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)

    job=hasher.launch("ignored@configured-target","/scratch/infra126","run-1",_candidates())

    assert [call[0] for call in transport.calls]==["ssh","scp_put","scp_put","ssh"]
    assert "mkdir -p" in transport.calls[0][1]
    assert transport.calls[0][2]["background"] is False
    assert transport.calls[3][2]["background"] is True
    assert job.pid==4242
    assert job.ssh_target==transport.target


def test_launch_command_closes_remote_stdin_before_stdout_redirect(tmp_path):
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)

    hasher.launch("ignored","/scratch/infra126","run-1",_candidates())

    launch_cmd=transport.calls[3][1]
    assert "< /dev/null > " in launch_cmd
    assert launch_cmd.index("< /dev/null")<launch_cmd.index("stdout.log")


def test_launch_command_wraps_backgrounding_in_a_subshell(tmp_path):
    # `cmdA && nohup cmdB &` backgrounds the ENTIRE `&&` chain as one async
    # job -- over an ssh pipe (no pty) this blocks the local client until
    # that whole job (including the long-running hash script) exits, not
    # just until the pid is recorded. Confirmed live against agent-1: the
    # launch ssh call hung to its 60s timeout despite `< /dev/null`. Fix:
    # the backgrounding step must be its own `( ... )` subshell so that
    # subshell (not the long-running job) is what finishes immediately.
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)

    hasher.launch("ignored","/scratch/infra126","run-1",_candidates())

    launch_cmd=transport.calls[3][1]
    assert " & echo $!" in launch_cmd
    subshell_open=launch_cmd.index("(")
    subshell_close=launch_cmd.rindex(")")
    assert subshell_open!=-1 and subshell_close>subshell_open
    assert launch_cmd.index("nohup")>subshell_open
    assert launch_cmd.index("echo $!")<subshell_close
    assert launch_cmd.rindex("cat ")>subshell_close


def test_launch_command_falls_back_when_nohup_is_missing(tmp_path):
    # QNAP QTS's busybox ash (nas-1) has no `nohup` binary at all --
    # confirmed live: "sh: nohup: command not found", which silently drops
    # the whole background job (stdout.log came back empty, no done/heartbeat
    # ever written). setsid IS present on QTS, so detect availability on the
    # remote side rather than hardcoding either tool.
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)

    hasher.launch("ignored","/scratch/infra126","run-1",_candidates())

    launch_cmd=transport.calls[3][1]
    assert "command -v nohup" in launch_cmd
    assert "command -v setsid" in launch_cmd
    assert "$RUNNER sh " in launch_cmd


def test_probe_and_terminate_route_through_transport(tmp_path):
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)
    job=RemoteJob(transport.target,"/scratch/run",123,"/scratch/run/results","/scratch/run/heartbeat","token")

    hasher.terminate(job)

    assert transport.calls[0][0]=="ssh"
    assert transport.calls[0][2]["check"] is False
    assert "kill 123" in transport.calls[0][1]

    transport.calls.clear()
    state,heartbeat=hasher._probe(job)

    assert transport.calls[0][0]=="ssh"
    assert transport.calls[0][2]["check"] is False
    assert state=="exited"
    assert heartbeat is None


def test_wait_fetches_results_through_transport(monkeypatch,tmp_path):
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)
    job=RemoteJob(transport.target,"/scratch/run",123,"/scratch/run/results","/scratch/run/heartbeat","token")
    monkeypatch.setattr(hasher,"_probe",lambda _:("done",1))

    results=hasher.wait(job)

    assert [call[0] for call in transport.calls]==["scp_get"]
    assert transport.calls[0][1]=="/scratch/run/results"
    assert len(results)==1
    assert results[0].status==HashOutcome.HASHED
    assert results[0].sha256=="deadbeef"


def test_transport_defaults_to_pubkey_when_not_injected(monkeypatch,tmp_path):
    calls=[]

    def fake_run(argv,**kwargs):
        calls.append((list(argv),dict(kwargs)))
        return SimpleNamespace(stdout="99\n",stderr="",returncode=0)

    monkeypatch.setattr("havnvard_bitrot.transport.subprocess.run",fake_run)
    helper=tmp_path/"remote_hash_batch.sh"
    helper.write_text("#!/bin/sh\n",encoding="utf-8")
    hasher=RemoteBatchHasher(helper,timeout_seconds=100,poll_seconds=0,heartbeat_stale_seconds=5)

    transport=hasher._transport_for("havnvard@agent-1")
    assert isinstance(transport,PubkeySshTransport)
    assert transport.target=="havnvard@agent-1"

    job=hasher.launch("havnvard@agent-1","/scratch/infra126","run-1",_candidates())

    assert job.ssh_target=="havnvard@agent-1"
    assert job.pid==99
    assert calls[0][0][0]=="ssh"
    assert calls[0][1]["stdin"] is subprocess.DEVNULL


def test_recovery_command_pubkey_shape_is_preserved(tmp_path):
    hasher=RemoteBatchHasher(tmp_path/"helper",transport=PubkeySshTransport("havnvard@agent-1"))
    job=RemoteJob("havnvard@agent-1","/scratch/run",123,"/scratch/run/results","/scratch/run/heartbeat","tok-1")

    command=hasher.recovery_command(job)

    assert command.startswith("ssh havnvard@agent-1 ")
    assert "/scratch/run/token" in command
    assert "tok-1" in command
    assert "kill 123" in command
    assert "pkill" not in command


def test_recovery_command_uses_sshpass_prefix_for_sshpass_hosts(tmp_path):
    transport=FakeTransport()
    hasher=_hasher(transport,tmp_path)
    job=RemoteJob(transport.target,"/scratch/run",123,"/scratch/run/results","/scratch/run/heartbeat","tok-1")

    command=hasher.recovery_command(job)

    assert command.startswith("sshpass -f")
    assert "kill 123" in command
    assert "tok-1" in command
