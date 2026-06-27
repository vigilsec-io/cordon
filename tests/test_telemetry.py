"""Tests for anonymous telemetry — local-only, opt-out, never leaks sensitive data."""
import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from vigil.rules.base import Finding, Severity
from vigil import telemetry


def _finding(rule_id="VGL-D001", sev=Severity.CRITICAL, file_ext=".yml"):
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message="test finding",
        file_path=Path(f"docker-compose{file_ext}"),
        line=1,
    )


def test_record_writes_event(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True)

    lines = events_file.read_text().strip().splitlines()
    assert len(lines) == 1
    ev = json.loads(lines[0])
    assert ev["rule_id"] == "VGL-D001"
    assert ev["severity"] == "CRITICAL"
    assert ev["file_ext"] == ".yml"
    assert "ts" in ev


def test_record_multiple_findings(tmp_path):
    events_file = tmp_path / "events.jsonl"
    findings = [
        _finding("VGL-D001", Severity.CRITICAL, ".yml"),
        _finding("VGL-S001", Severity.HIGH, ".py"),
    ]
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record(findings, telemetry_enabled=True)

    lines = events_file.read_text().strip().splitlines()
    assert len(lines) == 2


def test_record_no_path_in_event(tmp_path):
    """Event must never contain file path — only the extension."""
    events_file = tmp_path / "events.jsonl"
    f = _finding()
    f.file_path = Path("/home/user/super_secret_project/docker-compose.yml")
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([f], telemetry_enabled=True)

    ev = json.loads(events_file.read_text().strip())
    assert "path" not in ev
    assert "super_secret" not in str(ev)
    assert ev["file_ext"] == ".yml"


def test_record_no_snippet_in_event(tmp_path):
    """Event must never contain the finding message or snippet."""
    events_file = tmp_path / "events.jsonl"
    f = _finding()
    f.snippet = "sk_live_supersecretkey123456"  # vigil: ignore
    f.message = "Hardcoded Stripe live key found"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([f], telemetry_enabled=True)

    raw = events_file.read_text()
    assert "supersecretkey" not in raw
    assert "Hardcoded" not in raw


def test_opted_out_via_env(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.dict(os.environ, {"VIGIL_NO_TELEMETRY": "1"}), \
         patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True)

    assert not events_file.exists()


def test_opted_out_via_config(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=False)

    assert not events_file.exists()


def test_env_zero_not_opted_out(tmp_path):
    """VIGIL_NO_TELEMETRY=0 means NOT opted out — telemetry enabled."""
    events_file = tmp_path / "events.jsonl"
    with patch.dict(os.environ, {"VIGIL_NO_TELEMETRY": "0"}), \
         patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True)

    assert events_file.exists()


def test_empty_findings_no_write(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([], telemetry_enabled=True)

    assert not events_file.exists()


def test_summary_empty_when_no_file(tmp_path):
    with patch.object(telemetry, "_EVENTS_FILE", tmp_path / "events.jsonl"):
        result = telemetry.summary()
    assert result == {}


def test_summary_counts_by_rule(tmp_path):
    events_file = tmp_path / "events.jsonl"
    findings = [
        _finding("VGL-D001"),
        _finding("VGL-D001"),
        _finding("VGL-S001"),
    ]
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record(findings, telemetry_enabled=True)
        result = telemetry.summary()

    assert result["total_findings"] == 3
    assert result["by_rule"]["VGL-D001"] == 2
    assert result["by_rule"]["VGL-S001"] == 1


def test_engine_respects_telemetry_false(tmp_path):
    """Engine with telemetry_enabled=False must not write events."""
    from vigil.engine import Engine
    from vigil.rules.docker import DockerPortExposureRule as DockerPortBindingRule

    events_file = tmp_path / "events.jsonl"
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  app:\n    ports:\n      - \"8080:8080\"\n")

    engine = Engine(rules=[DockerPortBindingRule()], telemetry_enabled=False)
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        engine.scan(compose)

    assert not events_file.exists()
