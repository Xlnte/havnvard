import pytest

from havnvard_bitrot.alerts import fingerprint
from havnvard_bitrot.monitor import _send_reserved


def test_alert_fingerprint_is_stable_and_path_sensitive():
    a=fingerprint("possible_corruption","spark","/a","x")
    b=fingerprint("possible_corruption","spark","/a","x")
    c=fingerprint("possible_corruption","spark","/b","x")
    assert a==b
    assert a!=c
    assert len(a)==64


class _FailingSink:
    def send(self, event_type, severity, payload):
        raise RuntimeError("delivery failed")


class _AlertRepository:
    def __init__(self):
        self.sent=[]
        self.failed=[]

    def reserve_alert(self,*args,**kwargs):
        return True

    def mark_alert_sent(self,key):
        self.sent.append(key)

    def mark_alert_failed(self,key,error):
        self.failed.append((key,error))


def test_failed_delivery_releases_persisted_alert_lease():
    repo=_AlertRepository()
    with pytest.raises(RuntimeError,match="delivery failed"):
        _send_reserved(repo,_FailingSink(),"key","event","urgent","spark",None,{},suppress_hours=1)
    assert repo.sent==[]
    assert repo.failed==[("key","delivery failed")]
