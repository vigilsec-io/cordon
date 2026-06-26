from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import subprocess
import pytest
from vigil.rules.trivy import TrivyIacScanRule
from vigil.rules.base import Severity

rule = TrivyIacScanRule()

_TRIVY_JSON_ONE_HIGH = json.dumps({
    "Results": [{
        "Misconfigurations": [{
            "ID": "DS002",
            "Title": "Image user should not be root",
            "Severity": "HIGH",
            "Resolution": "Add a non-root USER directive",
            "Message": "Avoid running as root",
        }]
    }]
})

_TRIVY_JSON_EMPTY = json.dumps({"Results": []})


def test_trivy_not_installed_returns_empty(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\n")
    with patch("subprocess.run", side_effect=FileNotFoundError):
        findings = rule.check(f)
    assert findings == []


def test_trivy_timeout_returns_empty(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\n")
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="trivy", timeout=60)):
        findings = rule.check(f)
    assert findings == []


def test_trivy_high_finding_parsed(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\n")
    mock_proc = MagicMock()
    mock_proc.stdout = _TRIVY_JSON_ONE_HIGH
    with patch("subprocess.run", return_value=mock_proc):
        findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "DS002" in findings[0].message


def test_trivy_empty_results_returns_empty(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\n")
    mock_proc = MagicMock()
    mock_proc.stdout = _TRIVY_JSON_EMPTY
    with patch("subprocess.run", return_value=mock_proc):
        findings = rule.check(f)
    assert findings == []


def test_trivy_invalid_json_returns_empty(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\n")
    mock_proc = MagicMock()
    mock_proc.stdout = "not json"
    with patch("subprocess.run", return_value=mock_proc):
        findings = rule.check(f)
    assert findings == []


def test_applies_to_dockerfile(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_terraform(tmp_path):
    f = tmp_path / "main.tf"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_does_not_apply_to_generic_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("")
    assert rule.applies_to(f) is False
