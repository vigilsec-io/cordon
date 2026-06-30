from pathlib import Path
import pytest
from vigil.engine import Engine
from vigil.rules import (
    DockerPortExposureRule, DockerfileRootUserRule,
    DockerfileLatestTagRule, AwsAccessKeyRule, Severity, SEVERITY_ORDER,
)


def test_scan_unsafe_compose_returns_findings(unsafe_compose):
    engine = Engine([DockerPortExposureRule()])
    findings = engine.scan(unsafe_compose)
    assert len(findings) > 0


def test_scan_safe_compose_no_findings(safe_compose):
    engine = Engine([DockerPortExposureRule()])
    findings = engine.scan(safe_compose)
    assert findings == []


def test_scan_nonexistent_file_returns_empty():
    engine = Engine()
    findings = engine.scan(Path("/nonexistent/does_not_exist.yml"))
    assert findings == []


def test_blocking_true_on_critical_finding(unsafe_compose):
    engine = Engine([DockerPortExposureRule()])
    findings = engine.scan(unsafe_compose)
    assert Engine.blocking(findings) is True


def test_blocking_false_on_empty():
    assert Engine.blocking([]) is False


def test_dockerfile_missing_user_flagged(unsafe_dockerfile):
    engine = Engine([DockerfileRootUserRule()])
    findings = engine.scan(unsafe_dockerfile)
    assert len(findings) == 1
    assert "root" in findings[0].message.lower() or "USER" in findings[0].message


def test_dockerfile_with_user_is_clean(safe_dockerfile):
    engine = Engine([DockerfileRootUserRule()])
    findings = engine.scan(safe_dockerfile)
    assert findings == []


def test_dockerfile_latest_tag_flagged(unsafe_dockerfile):
    engine = Engine([DockerfileLatestTagRule()])
    findings = engine.scan(unsafe_dockerfile)
    assert len(findings) == 1
    assert "latest" in findings[0].message.lower() or "unpinned" in findings[0].message.lower()


def test_findings_sorted_by_severity(unsafe_compose):
    engine = Engine([DockerPortExposureRule(), DockerfileRootUserRule()])
    findings = engine.scan(unsafe_compose)
    if len(findings) > 1:
        orders = [SEVERITY_ORDER[f.severity] for f in findings]
        assert orders == sorted(orders)


def test_scan_dir_finds_unsafe_files(tmp_path):
    compose = tmp_path / "docker-compose.yml"
    compose.write_text('"8000:8000"\n"5432:5432"\n')
    engine = Engine([DockerPortExposureRule()])
    results = engine.scan_dir(tmp_path)
    assert compose in results
    assert len(results[compose]) == 2


def test_scan_dir_skips_venv(tmp_path):
    venv_dir = tmp_path / ".venv"
    venv_dir.mkdir()
    compose = venv_dir / "docker-compose.yml"
    compose.write_text('"8000:8000"\n')
    engine = Engine([DockerPortExposureRule()])
    results = engine.scan_dir(tmp_path)
    assert compose not in results


def test_rule_not_applied_to_wrong_file_type(tmp_path):
    py_file = tmp_path / "main.py"
    py_file.write_text('"8000:8000"\n')
    engine = Engine([DockerPortExposureRule()])
    findings = engine.scan(py_file)
    # DockerPortExposureRule.applies_to() returns False for .py
    assert findings == []


def test_pragma_allowlist_suppresses_finding(tmp_path):
    """'# pragma: allowlist secret' on the same line suppresses a finding."""
    from vigil.rules.base import Rule, Finding, Severity

    class AlwaysRule(Rule):
        id = "VGL-TEST-SUP"
        name = "test"
        severity = Severity.HIGH
        def applies_to(self, path): return True
        def check(self, path):
            return [Finding(rule_id=self.id, severity=self.severity,
                            message="hit", file_path=path, line=1)]

    f = tmp_path / "secret.py"
    f.write_text("TOKEN = 'abc'  # pragma: allowlist secret\n")
    engine = Engine(rules=[AlwaysRule()], telemetry_enabled=False)
    findings = engine.scan(f)
    assert findings == []


def test_vigil_ignore_still_suppresses(tmp_path):
    """'# vigil: ignore' continues to suppress findings after pragma addition."""
    from vigil.rules.base import Rule, Finding, Severity

    class AlwaysRule(Rule):
        id = "VGL-TEST-IGN"
        name = "test"
        severity = Severity.HIGH
        def applies_to(self, path): return True
        def check(self, path):
            return [Finding(rule_id=self.id, severity=self.severity,
                            message="hit", file_path=path, line=1)]

    f = tmp_path / "secret.py"
    f.write_text("TOKEN = 'abc'  # vigil: ignore\n")
    engine = Engine(rules=[AlwaysRule()], telemetry_enabled=False)
    findings = engine.scan(f)
    assert findings == []
