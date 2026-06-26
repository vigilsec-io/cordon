from pathlib import Path
import json
import pytest
from vigil.reporter import report_sarif, report_json
from vigil.rules.base import Finding, Severity


def _make_finding(rule_id: str = "VGL-D001", sev: Severity = Severity.CRITICAL,
                  path: Path = Path("/tmp/docker-compose.yml"), line: int | None = 5) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=sev,
        message="Test finding",
        file_path=path,
        line=line,
        fix="Fix it",
    )


def test_sarif_is_valid_json():
    p = Path("/app/docker-compose.yml")
    results = {p: [_make_finding(path=p)]}
    output = report_sarif(results)
    data = json.loads(output)
    assert isinstance(data, dict)


def test_sarif_schema_and_version():
    results = {Path("/app/f.yml"): [_make_finding(path=Path("/app/f.yml"))]}
    data = json.loads(report_sarif(results))
    assert data["version"] == "2.1.0"
    assert "sarif" in data["$schema"]


def test_sarif_finding_appears_in_results():
    p = Path("/app/docker-compose.yml")
    finding = _make_finding(path=p, sev=Severity.HIGH)
    data = json.loads(report_sarif({p: [finding]}))
    results = data["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "VGL-D001"
    assert results[0]["level"] == "error"
    assert results[0]["locations"][0]["physicalLocation"]["region"]["startLine"] == 5


def test_sarif_critical_maps_to_error():
    p = Path("/tmp/f.py")
    data = json.loads(report_sarif({p: [_make_finding(sev=Severity.CRITICAL, path=p)]}))
    assert data["runs"][0]["results"][0]["level"] == "error"


def test_sarif_medium_maps_to_warning():
    p = Path("/tmp/f.py")
    data = json.loads(report_sarif({p: [_make_finding(sev=Severity.MEDIUM, path=p)]}))
    assert data["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_empty_results():
    data = json.loads(report_sarif({}))
    assert data["runs"][0]["results"] == []


def test_sarif_deduplicates_rules():
    p = Path("/tmp/f.yml")
    findings = [
        _make_finding("VGL-D001", path=p),
        _make_finding("VGL-D001", path=p),
        _make_finding("VGL-S001", path=p),
    ]
    data = json.loads(report_sarif({p: findings}))
    rule_ids = [r["id"] for r in data["runs"][0]["tool"]["driver"]["rules"]]
    assert rule_ids.count("VGL-D001") == 1
    assert len(rule_ids) == 2


def test_sarif_no_line_defaults_to_1():
    p = Path("/tmp/f.py")
    finding = _make_finding(path=p, line=None)
    data = json.loads(report_sarif({p: [finding]}))
    region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 1
