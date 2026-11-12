from havnvard_bitrot.classifier import classify_divergence


def test_log_with_real_metadata_change_is_mutable():
    result = classify_divergence("/var/log/syslog",1_000_000_000,2_000_000_000,10,20)
    assert result.score == 99
    assert result.divergence_type == "legitimate_drift"
    assert result.auto_accept_baseline


def test_sqlite_is_mutable_when_written():
    result = classify_divergence("/home/user/app.sqlite",1_000_000_000,2_000_000_000,10,20)
    assert result.score == 98
    assert result.explicit_mutable_rule
    assert result.auto_accept_baseline


def test_frozen_metadata_overrides_mutable_path():
    result = classify_divergence("/var/log/syslog",1,1,10,10)
    assert result.score == 5
    assert result.divergence_type == "unconfirmed_corruption"
    assert not result.auto_accept_baseline


def test_immutable_path_remains_suspicious_even_if_metadata_changed():
    result = classify_divergence("/etc/hostname",1,2,10,11)
    assert result.score <= 25
    assert result.explicit_immutable_rule
    assert result.divergence_type == "unconfirmed_corruption"


def test_unknown_file_with_changed_mtime_and_size_is_likely_legitimate():
    result = classify_divergence("/home/user/notes.txt",1_000_000_000,2_000_000_000,10,20)
    assert result.score == 90
    assert not result.auto_accept_baseline  # only explicit mutable rules auto-advance baseline


def test_critical_override_alerts_even_for_log():
    result = classify_divergence("/var/log/critical.log",1_000_000_000,2_000_000_000,10,20,is_critical=True)
    assert result.score == 15
    assert result.divergence_type == "unconfirmed_corruption"


def test_untrusted_metadata_disables_frozen_metadata_signal_and_auto_accept():
    result=classify_divergence(
        "/var/log/app.log",100,100,10,10,metadata_trusted=False
    )
    assert result.score==99
    assert result.divergence_type=="legitimate_drift"
    assert result.auto_accept_baseline is False
    assert "untrusted" in result.reason
