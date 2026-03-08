"""Unit tests for YAML policy loader."""

from pathlib import Path

import pytest
import yaml

from sentinel.policy.loader import PolicyLoader, _parse_rule, load_policy_file


def _write_policy(path: Path, data: dict) -> None:
    path.write_text(yaml.dump(data))


def _rule_data(**kwargs) -> dict:
    defaults = dict(
        id="R1",
        domain="config",
        check="gateway.bind",
        condition="not_in",
        value="loopback,localhost",
        severity="HIGH",
        action="ALERT",
        message="exposed",
    )
    defaults.update(kwargs)
    return defaults


# ── _parse_rule ───────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestParseRule:
    def test_all_fields_parsed(self):
        r = _parse_rule(_rule_data())
        assert r.id == "R1"
        assert r.domain == "config"
        assert r.check == "gateway.bind"
        assert r.condition == "not_in"
        assert r.value == "loopback,localhost"
        assert r.severity == "HIGH"
        assert r.action == "ALERT"
        assert r.message == "exposed"

    def test_action_uppercased(self):
        r = _parse_rule(_rule_data(action="alert"))
        assert r.action == "ALERT"

    def test_defaults_applied(self):
        r = _parse_rule({"id": "X"})
        assert r.condition == "equals"
        assert r.severity == "MEDIUM"
        assert r.action == "ALERT"
        assert r.auto_remediate is False

    def test_value_coerced_to_string(self):
        r = _parse_rule(_rule_data(value=42))
        assert r.value == "42"

    def test_auto_remediate_parsed(self):
        r = _parse_rule(_rule_data(auto_remediate=True))
        assert r.auto_remediate is True


# ── load_policy_file ──────────────────────────────────────────────────────────


@pytest.mark.unit
class TestLoadPolicyFile:
    def test_loads_valid_yaml(self, tmp_path):
        p = tmp_path / "pol.yaml"
        _write_policy(p, {"name": "test", "version": "1", "rules": [_rule_data()]})
        policy = load_policy_file(p)
        assert policy is not None
        assert policy.name == "test"
        assert len(policy.rules) == 1

    def test_missing_file_returns_none(self, tmp_path):
        assert load_policy_file(tmp_path / "nonexistent.yaml") is None

    def test_invalid_yaml_returns_none(self, tmp_path):
        p = tmp_path / "bad.yaml"
        p.write_text(":\t: invalid: yaml: [[")
        assert load_policy_file(p) is None

    def test_empty_file_returns_policy_with_no_rules(self, tmp_path):
        p = tmp_path / "empty.yaml"
        p.write_text("")
        policy = load_policy_file(p)
        assert policy is not None
        assert policy.rules == []

    def test_name_defaults_to_stem(self, tmp_path):
        p = tmp_path / "my_policy.yaml"
        _write_policy(p, {"rules": []})
        assert load_policy_file(p).name == "my_policy"

    def test_version_coerced_to_string(self, tmp_path):
        p = tmp_path / "p.yaml"
        _write_policy(p, {"version": 2, "rules": []})
        assert load_policy_file(p).version == "2"

    def test_multiple_rules_loaded(self, tmp_path):
        p = tmp_path / "multi.yaml"
        _write_policy(p, {"name": "multi", "rules": [_rule_data(id="A"), _rule_data(id="B")]})
        policy = load_policy_file(p)
        assert len(policy.rules) == 2


# ── PolicyLoader ──────────────────────────────────────────────────────────────


@pytest.mark.unit
class TestPolicyLoader:
    def test_empty_dir_yields_no_rules(self, tmp_path):
        loader = PolicyLoader(tmp_path)
        assert loader.rules == []

    def test_nonexistent_dir_yields_no_rules(self, tmp_path):
        loader = PolicyLoader(tmp_path / "missing")
        assert loader.rules == []

    def test_loads_yaml_files(self, tmp_path):
        _write_policy(tmp_path / "p.yaml", {"rules": [_rule_data(id="R1")]})
        loader = PolicyLoader(tmp_path)
        assert len(loader.rules) == 1
        assert loader.rules[0].id == "R1"

    def test_ignores_non_yaml_files(self, tmp_path):
        (tmp_path / "p.yaml").write_text(yaml.dump({"rules": [_rule_data()]}))
        (tmp_path / "notes.txt").write_text("notes")
        loader = PolicyLoader(tmp_path)
        assert len(loader.rules) == 1

    def test_rules_from_multiple_files_merged(self, tmp_path):
        _write_policy(tmp_path / "a.yaml", {"rules": [_rule_data(id="A")]})
        _write_policy(tmp_path / "b.yaml", {"rules": [_rule_data(id="B")]})
        loader = PolicyLoader(tmp_path)
        ids = {r.id for r in loader.rules}
        assert ids == {"A", "B"}

    def test_reload_picks_up_new_file(self, tmp_path):
        loader = PolicyLoader(tmp_path)
        assert len(loader.rules) == 0
        _write_policy(tmp_path / "new.yaml", {"rules": [_rule_data(id="NEW")]})
        loader.reload()
        assert len(loader.rules) == 1

    def test_reload_removes_deleted_file(self, tmp_path):
        p = tmp_path / "p.yaml"
        _write_policy(p, {"rules": [_rule_data()]})
        loader = PolicyLoader(tmp_path)
        assert len(loader.rules) == 1
        p.unlink()
        loader.reload()
        assert len(loader.rules) == 0

    def test_policies_property_returns_list(self, tmp_path):
        _write_policy(tmp_path / "p.yaml", {"name": "test", "rules": [_rule_data()]})
        loader = PolicyLoader(tmp_path)
        assert len(loader.policies) == 1
        assert loader.policies[0].name == "test"

    def test_files_loaded_in_sorted_order(self, tmp_path):
        _write_policy(tmp_path / "b.yaml", {"name": "B", "rules": [_rule_data(id="B")]})
        _write_policy(tmp_path / "a.yaml", {"name": "A", "rules": [_rule_data(id="A")]})
        loader = PolicyLoader(tmp_path)
        ids = [r.id for r in loader.rules]
        assert ids == ["A", "B"]  # sorted alphabetically
