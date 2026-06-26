from pathlib import Path
import pytest
from vigil.config import VigilConfig, load_config
from vigil.rules import DEFAULT_RULES


def test_default_config_is_empty():
    c = VigilConfig()
    assert c.disabled_rules == []
    assert c.min_severity is None
    assert c.exclude_paths == []


def test_no_vigilrc_returns_defaults(tmp_path):
    config = load_config(tmp_path)
    assert config.disabled_rules == []
    assert config.min_severity is None
    assert config.exclude_paths == []


def test_vigilrc_loaded_from_directory(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-T001"]\n')
    config = load_config(tmp_path)
    assert "VGL-T001" in config.disabled_rules


def test_vigilrc_loaded_from_file_path(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-N001"]\n')
    f = tmp_path / "docker-compose.yml"
    f.write_text("")
    config = load_config(f)
    assert "VGL-N001" in config.disabled_rules


def test_vigilrc_walks_up_to_parent(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-D001"]\n')
    child = tmp_path / "services" / "api"
    child.mkdir(parents=True)
    config = load_config(child)
    assert "VGL-D001" in config.disabled_rules


def test_child_vigilrc_takes_precedence(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-T001"]\n')
    child = tmp_path / "subproject"
    child.mkdir()
    (child / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-N001"]\n')
    config = load_config(child)
    assert "VGL-N001" in config.disabled_rules
    assert "VGL-T001" not in config.disabled_rules


def test_min_severity_parsed(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'min_severity = "HIGH"\n')
    config = load_config(tmp_path)
    assert config.min_severity == "HIGH"


def test_exclude_paths_parsed(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'exclude_paths = ["vendor", "legacy"]\n')
    config = load_config(tmp_path)
    assert "vendor" in config.exclude_paths
    assert "legacy" in config.exclude_paths


def test_invalid_toml_returns_defaults(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b"this is not [[[valid toml")
    config = load_config(tmp_path)
    assert config.disabled_rules == []


def test_disabled_rule_filtered_from_default_rules(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(b'disabled_rules = ["VGL-D001", "VGL-T001"]\n')
    config = load_config(tmp_path)
    rules = [r for r in DEFAULT_RULES if r.id not in config.disabled_rules]
    ids = [r.id for r in rules]
    assert "VGL-D001" not in ids
    assert "VGL-T001" not in ids
    assert "VGL-S001" in ids


def test_multiple_fields_parsed(tmp_path):
    (tmp_path / ".vigilrc").write_bytes(
        b'disabled_rules = ["VGL-T001"]\n'
        b'min_severity = "MEDIUM"\n'
        b'exclude_paths = ["vendor"]\n'
    )
    config = load_config(tmp_path)
    assert config.disabled_rules == ["VGL-T001"]
    assert config.min_severity == "MEDIUM"
    assert config.exclude_paths == ["vendor"]
