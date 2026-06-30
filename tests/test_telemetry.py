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
    assert result["by_rule"]["VGL-D001"]["count"] == 2
    assert result["by_rule"]["VGL-S001"]["count"] == 1


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


# ── FP event recording (ticket #26) ──────────────────────────────────────────

def test_record_with_fp_true_adds_fp_field(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True, fp=True)

    ev = json.loads(events_file.read_text().strip())
    assert ev.get("fp") is True


def test_record_without_fp_has_no_fp_field(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True)

    ev = json.loads(events_file.read_text().strip())
    assert "fp" not in ev


def test_opt_out_suppresses_fp_events(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=False, fp=True)

    assert not events_file.exists()


def test_summary_fp_count(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding("VGL-S001"), _finding("VGL-S001")], telemetry_enabled=True)
        telemetry.record([_finding("VGL-S001")], telemetry_enabled=True, fp=True)
        result = telemetry.summary()

    assert result["total_fp"] == 1
    assert result["by_rule"]["VGL-S001"]["fp_count"] == 1
    assert result["by_rule"]["VGL-S001"]["count"] == 2


def test_summary_precision_with_fp(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding("VGL-D001")] * 9, telemetry_enabled=True)
        telemetry.record([_finding("VGL-D001")], telemetry_enabled=True, fp=True)
        result = telemetry.summary()

    prec = result["by_rule"]["VGL-D001"]["precision"]
    assert abs(prec - 0.9) < 0.01


def test_summary_precision_no_fp_is_one(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding("VGL-D001")] * 5, telemetry_enabled=True)
        result = telemetry.summary()

    assert result["by_rule"]["VGL-D001"]["precision"] == 1.0
    assert result["by_rule"]["VGL-D001"]["fp_count"] == 0


def test_summary_fp_only_rule_count_is_zero(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding("VGL-D001")], telemetry_enabled=True)
        telemetry.record([_finding("VGL-S999")], telemetry_enabled=True, fp=True)
        result = telemetry.summary()

    assert result["by_rule"]["VGL-S999"]["count"] == 0
    assert result["by_rule"]["VGL-S999"]["fp_count"] == 1
    assert result["by_rule"]["VGL-S999"]["precision"] == 0.0


def test_summary_by_severity_excludes_fp_events(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding("VGL-D001", Severity.CRITICAL)], telemetry_enabled=True)
        telemetry.record([_finding("VGL-S001", Severity.HIGH)], telemetry_enabled=True, fp=True)
        result = telemetry.summary()

    assert result["by_severity"].get("CRITICAL", 0) == 1
    assert result["by_severity"].get("HIGH", 0) == 0  # was suppressed FP


def test_summary_total_fp_field_present(tmp_path):
    events_file = tmp_path / "events.jsonl"
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        telemetry.record([_finding()], telemetry_enabled=True)
        result = telemetry.summary()

    assert "total_fp" in result
    assert result["total_fp"] == 0


# ── first_seen / last_seen (ticket #27) ──────────────────────────────────────

def test_summary_has_first_last_seen(tmp_path):
    events_file = tmp_path / "events.jsonl"
    rows = [
        {"ts": "2026-06-27T10:00:00+00:00", "rule_id": "VGL-D001", "severity": "CRITICAL", "file_ext": ".yml"},
        {"ts": "2026-06-29T10:00:00+00:00", "rule_id": "VGL-D001", "severity": "CRITICAL", "file_ext": ".yml"},
    ]
    events_file.parent.mkdir(parents=True, exist_ok=True)
    events_file.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        result = telemetry.summary()

    assert result["by_rule"]["VGL-D001"]["first_seen"] == "2026-06-27"
    assert result["by_rule"]["VGL-D001"]["last_seen"] == "2026-06-29"


def test_summary_first_equals_last_single_event(tmp_path):
    events_file = tmp_path / "events.jsonl"
    row = {"ts": "2026-06-28T12:00:00+00:00", "rule_id": "VGL-S001", "severity": "HIGH", "file_ext": ".py"}
    events_file.parent.mkdir(parents=True, exist_ok=True)
    events_file.write_text(json.dumps(row) + "\n")

    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        result = telemetry.summary()

    rule = result["by_rule"]["VGL-S001"]
    assert rule["first_seen"] == rule["last_seen"] == "2026-06-28"


def test_summary_first_last_scan_timestamps(tmp_path):
    events_file = tmp_path / "events.jsonl"
    rows = [
        {"ts": "2026-06-25T10:00:00+00:00", "rule_id": "VGL-D001", "severity": "CRITICAL", "file_ext": ".yml"},
        {"ts": "2026-06-30T10:00:00+00:00", "rule_id": "VGL-S001", "severity": "HIGH", "file_ext": ".py"},
    ]
    events_file.parent.mkdir(parents=True, exist_ok=True)
    events_file.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        result = telemetry.summary()

    assert result["first_scan"] == "2026-06-25"
    assert result["last_scan"] == "2026-06-30"


# ── Engine suppression + FP (ticket #26) ─────────────────────────────────────

def test_engine_records_fp_on_vigil_ignore(tmp_path):
    from vigil.engine import Engine
    from vigil.rules.base import Rule, Finding, Severity

    class AlwaysRule(Rule):
        id = "VGL-TEST-FP1"
        name = "test"
        severity = Severity.HIGH
        def applies_to(self, path): return True
        def check(self, path):
            return [Finding(rule_id=self.id, severity=self.severity,
                            message="hit", file_path=path, line=1)]

    events_file = tmp_path / "events.jsonl"
    f = tmp_path / "code.py"
    f.write_text("x = 1  # vigil: ignore\n")

    engine = Engine(rules=[AlwaysRule()], telemetry_enabled=True)
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        findings = engine.scan(f)
        result = telemetry.summary()

    assert findings == []
    assert result.get("total_fp", 0) == 1
    assert result.get("total_findings", 0) == 0
    assert result["by_rule"]["VGL-TEST-FP1"]["fp_count"] == 1


def test_engine_records_fp_on_pragma_allowlist(tmp_path):
    from vigil.engine import Engine
    from vigil.rules.base import Rule, Finding, Severity

    class AlwaysRule(Rule):
        id = "VGL-TEST-FP2"
        name = "test"
        severity = Severity.HIGH
        def applies_to(self, path): return True
        def check(self, path):
            return [Finding(rule_id=self.id, severity=self.severity,
                            message="hit", file_path=path, line=1)]

    events_file = tmp_path / "events.jsonl"
    f = tmp_path / "code.py"
    f.write_text("x = 1  # pragma: allowlist secret\n")

    engine = Engine(rules=[AlwaysRule()], telemetry_enabled=True)
    with patch.object(telemetry, "_EVENTS_FILE", events_file):
        findings = engine.scan(f)
        result = telemetry.summary()

    assert findings == []
    assert result.get("total_fp", 0) == 1
    assert result["by_rule"]["VGL-TEST-FP2"]["fp_count"] == 1
