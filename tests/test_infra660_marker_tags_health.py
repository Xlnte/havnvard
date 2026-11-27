"""INFRA-660: a failed marker-tag prune reaches health under its own key; the drill verdict is untouched."""
import json

from backup import config, health


def _write(tmp_path, monkeypatch, rec):
    monkeypatch.setattr(config, "state_dir", lambda: tmp_path)
    (tmp_path / "pullback-drill.json").write_text(json.dumps(rec))


def test_prune_error_is_a_problem(tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, {"ok": True, "at": "2026-11-27T03:00:00+00:00", "summary": "s",
                                   "marker_tags_error": "restic tag rc=1"})
    name, ok, detail = health._drill_marker_tags_check()
    assert name == "pullback-drill-marker-tags" and ok is False and "rc=1" in detail


def test_clean_prune_is_ok(tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, {"ok": True, "at": "x", "summary": "s", "marker_tags_error": None})
    assert health._drill_marker_tags_check()[1] is True


def test_old_result_without_field_adds_no_check(tmp_path, monkeypatch):
    _write(tmp_path, monkeypatch, {"ok": True, "at": "x", "summary": "s"})
    assert health._drill_marker_tags_check() is None
