"""Tests for the config auditor."""
import pytest
from sentinel.analyzer.config_auditor import ConfigAuditor


@pytest.fixture
def auditor():
    return ConfigAuditor()


def _make_config(**kwargs):
    base = {
        "channels": {
            "discord": {"groupPolicy": "allowlist"},
            "telegram": {"groupPolicy": "allowlist"},
        },
        "gateway": {
            "bind": "loopback",
            "auth": {"mode": "token"},
        },
    }
    base.update(kwargs)
    return base


def test_conf01_discord_allowlist_passes(auditor):
    config = _make_config()
    findings = auditor.audit(config, "r1")
    conf01 = [f for f in findings if f.check_id == "CONF-01"]
    assert conf01
    assert conf01[0].result == "PASS"


def test_conf01_discord_open_fails(auditor):
    config = _make_config()
    config["channels"]["discord"]["groupPolicy"] = "open"
    findings = auditor.audit(config, "r1")
    conf01 = [f for f in findings if f.check_id == "CONF-01"]
    assert conf01
    assert conf01[0].result == "FAIL"
    assert conf01[0].severity == "CRITICAL"


def test_conf02_telegram_not_configured_skipped(auditor):
    config = {"channels": {}, "gateway": {"bind": "loopback", "auth": {"mode": "token"}}}
    findings = auditor.audit(config, "r1")
    conf02 = [f for f in findings if f.check_id == "CONF-02"]
    assert len(conf02) == 0


def test_conf02_telegram_open_fails(auditor):
    config = _make_config()
    config["channels"]["telegram"]["groupPolicy"] = "open"
    findings = auditor.audit(config, "r1")
    conf02 = [f for f in findings if f.check_id == "CONF-02"]
    assert conf02
    assert conf02[0].result == "FAIL"


def test_conf03_loopback_passes(auditor):
    config = _make_config()
    findings = auditor.audit(config, "r1")
    conf03 = [f for f in findings if f.check_id == "CONF-03"]
    assert len(conf03) == 0  # no finding means pass


def test_conf03_network_bind_fails(auditor):
    config = _make_config()
    config["gateway"]["bind"] = "0.0.0.0"
    findings = auditor.audit(config, "r1")
    conf03 = [f for f in findings if f.check_id == "CONF-03"]
    assert conf03
    assert conf03[0].result == "FAIL"


def test_conf04_token_auth_passes(auditor):
    config = _make_config()
    findings = auditor.audit(config, "r1")
    conf04 = [f for f in findings if f.check_id == "CONF-04"]
    assert len(conf04) == 0


def test_conf04_none_auth_fails(auditor):
    config = _make_config()
    config["gateway"]["auth"]["mode"] = "none"
    findings = auditor.audit(config, "r1")
    conf04 = [f for f in findings if f.check_id == "CONF-04"]
    assert conf04
    assert conf04[0].result == "FAIL"


def test_conf05_credential_in_config_fails(auditor):
    config = _make_config()
    config["auth_token"] = "sk-ant-api03-" + "X" * 30
    findings = auditor.audit(config, "r1")
    conf05 = [f for f in findings if f.check_id == "CONF-05"]
    assert conf05
    assert conf05[0].result == "FAIL"


def test_conf06_yolo_fails(auditor):
    config = _make_config()
    config["yolo"] = True
    findings = auditor.audit(config, "r1")
    conf06 = [f for f in findings if f.check_id == "CONF-06"]
    assert conf06
    assert conf06[0].result == "FAIL"
    assert conf06[0].severity == "CRITICAL"
