from __future__ import annotations

from types import SimpleNamespace

from havnvard_bitrot.waitingroom import WaitingRoomGate


def test_waitingroom_retries_until_admitted(monkeypatch):
    responses=iter([1,1,0])
    waits=[]
    monkeypatch.setattr("havnvard_bitrot.waitingroom.subprocess.run",lambda *a,**k: SimpleNamespace(returncode=next(responses)))
    monkeypatch.setattr("havnvard_bitrot.waitingroom.time.sleep",lambda _: None)
    ticks=iter([0.0,1.0,2.0,3.0])
    monkeypatch.setattr("havnvard_bitrot.waitingroom.time.monotonic",lambda: next(ticks))
    gate=WaitingRoomGate("acquire","release")
    assert gate.acquire("r","h","A",max_wait_seconds=10,retry_seconds=1,on_wait=waits.append)
    assert waits==[1,2]


def test_waitingroom_times_out_loudly(monkeypatch):
    monkeypatch.setattr("havnvard_bitrot.waitingroom.subprocess.run",lambda *a,**k: SimpleNamespace(returncode=1))
    monkeypatch.setattr("havnvard_bitrot.waitingroom.time.sleep",lambda _: None)
    ticks=iter([0.0,1.0,2.0,3.0])
    monkeypatch.setattr("havnvard_bitrot.waitingroom.time.monotonic",lambda: next(ticks))
    gate=WaitingRoomGate("acquire","release")
    assert not gate.acquire("r","h","A",max_wait_seconds=2,retry_seconds=1)
