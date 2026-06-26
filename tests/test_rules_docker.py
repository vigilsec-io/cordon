import pytest
from vigil.rules.docker import DockerPortExposureRule
from vigil.rules.base import Severity

rule = DockerPortExposureRule()


def test_unsafe_compose_flags_exposed_ports(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert len(findings) >= 2
    assert all(f.severity == Severity.CRITICAL for f in findings)
    ports_mentioned = " ".join(f.message for f in findings)
    assert "8000" in ports_mentioned
    assert "5432" in ports_mentioned


def test_safe_compose_returns_no_findings(safe_compose):
    findings = rule.check(safe_compose)
    assert findings == []


def test_nginx_ports_80_443_are_exempt(safe_compose):
    findings = rule.check(safe_compose)
    assert not any("80" in f.message or "443" in f.message for f in findings)


def test_finding_includes_127_fix(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert findings
    assert findings[0].fix is not None
    assert "127.0.0.1" in findings[0].fix


def test_finding_includes_line_number(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert all(f.line is not None and f.line > 0 for f in findings)


def test_applies_to_compose_yml(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_compose_override(tmp_path):
    f = tmp_path / "docker-compose.override.yml"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_does_not_apply_to_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("")
    assert rule.applies_to(f) is False


def test_does_not_apply_to_plain_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("")
    assert rule.applies_to(f) is False
