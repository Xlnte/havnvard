from types import SimpleNamespace

import pytest

from havnvard_bitrot.cli import _validate_run_integrations


def _settings(**overrides):
    values={
        "allow_null_integrations":False,
        "tg_command":"tg",
        "plane_command":"plane",
        "waitingroom_acquire_command":"acquire",
        "waitingroom_release_command":"release",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_production_run_refuses_missing_integrations():
    with pytest.raises(RuntimeError,match="INFRA126_TG_COMMAND"):
        _validate_run_integrations(_settings(tg_command=None))


def test_explicit_test_escape_hatch_allows_null_integrations():
    _validate_run_integrations(_settings(
        allow_null_integrations=True,tg_command=None,plane_command=None,
        waitingroom_acquire_command=None,waitingroom_release_command=None,
    ))
