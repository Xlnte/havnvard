"""INFRA-625: a check-in-only [device] (no backup paths) is not asked for a backup result."""
from backup import health


def test_backup_result_check_requires_device_paths():
    src = open(health.__file__).read()
    before = src.split('p = config.state_dir() / "backup-last.json"', 1)[0].rsplit("\n", 3)[-3:]
    assert any('get("paths")' in line for line in before)
