import hashlib

from havnvard_bitrot.hashing import hash_file
from havnvard_bitrot.types import HashOutcome


def test_hash_file_matches_sha256(tmp_path):
    path = tmp_path/"sample.bin"
    path.write_bytes(b"abc"*1000)
    result = hash_file(1,str(path))
    assert result.status == HashOutcome.HASHED
    assert result.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert result.size == 3000


def test_missing_file_is_reported_not_raised(tmp_path):
    result = hash_file(1,str(tmp_path/"missing"))
    assert result.status == HashOutcome.MISSING
    assert result.sha256 is None
