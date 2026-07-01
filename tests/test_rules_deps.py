from pathlib import Path
from unittest.mock import patch, MagicMock
import json
import subprocess
import pytest
from vigil.rules.deps import OsvScannerRule
from vigil.rules.base import Severity

rule = OsvScannerRule()

_OSV_JSON_ONE_VULN = json.dumps({
    "results": [{
        "source": {"path": "go.sum", "type": "lockfile"},
        "packages": [{
            "package": {"name": "github.com/pkg/errors", "version": "0.9.0", "ecosystem": "Go"},
            "vulnerabilities": [{"id": "GHSA-wxc4-f4m6-wwqv", "summary": "Prototype pollution"}],
        }],
    }]
})

_OSV_JSON_MULTIPLE_VULNS = json.dumps({
    "results": [{
        "source": {"path": "Cargo.lock", "type": "lockfile"},
        "packages": [
            {
                "package": {"name": "openssl", "version": "0.10.35", "ecosystem": "crates.io"},
                "vulnerabilities": [
                    {"id": "GHSA-v6hp-jr2h-5hv5", "summary": "Use after free"},
                    {"id": "GHSA-4p46-pwfr-66x6", "summary": "Memory corruption"},
                    {"id": "GHSA-9p3x-f35m-9922", "summary": "Buffer overflow"},
                    {"id": "GHSA-extra-1234-5678", "summary": "Extra"},
                ],
            },
            {
                "package": {"name": "time", "version": "0.1.43", "ecosystem": "crates.io"},
                "vulnerabilities": [{"id": "RUSTSEC-2020-0071", "summary": "Segfault"}],
            },
        ],
    }]
})

_OSV_JSON_NO_VULNS = json.dumps({
    "results": [{
        "source": {"path": "go.sum", "type": "lockfile"},
        "packages": [
            {
                "package": {"name": "github.com/pkg/errors", "version": "0.9.1", "ecosystem": "Go"},
                "vulnerabilities": [],
            }
        ],
    }]
})

_OSV_JSON_EMPTY_RESULTS = json.dumps({"results": []})


def _mock(stdout: str) -> MagicMock:
    m = MagicMock()
    m.stdout = stdout
    return m


# --- applies_to ---

def test_applies_to_go_sum(tmp_path):
    assert rule.applies_to(tmp_path / "go.sum") is True


def test_applies_to_cargo_lock(tmp_path):
    assert rule.applies_to(tmp_path / "Cargo.lock") is True


def test_applies_to_pom_xml(tmp_path):
    assert rule.applies_to(tmp_path / "pom.xml") is True


def test_applies_to_gradle_lockfile(tmp_path):
    assert rule.applies_to(tmp_path / "gradle.lockfile") is True


def test_does_not_apply_to_requirements_txt(tmp_path):
    assert rule.applies_to(tmp_path / "requirements.txt") is False


def test_does_not_apply_to_package_json(tmp_path):
    assert rule.applies_to(tmp_path / "package.json") is False


# --- osv-scanner not installed ---

def test_osv_not_installed_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("subprocess.run", side_effect=FileNotFoundError):
        assert rule.check(f) == []


def test_osv_tool_not_found_in_candidates_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value=None):
        assert rule.check(f) == []


def test_osv_timeout_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="osv-scanner", timeout=120)):
        assert rule.check(f) == []


# --- JSON parsing ---

def test_osv_one_vulnerability_parsed(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_ONE_VULN)):
            findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].rule_id == "VGL-DEP003"
    assert "github.com/pkg/errors" in findings[0].message
    assert "0.9.0" in findings[0].message
    assert "GHSA-wxc4-f4m6-wwqv" in findings[0].message


def test_osv_multiple_packages_creates_one_finding_each(tmp_path):
    f = tmp_path / "Cargo.lock"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_MULTIPLE_VULNS)):
            findings = rule.check(f)
    assert len(findings) == 2
    pkg_names = {f.message.split("@")[0] for f in findings}
    assert "openssl" in pkg_names
    assert "time" in pkg_names


def test_osv_vuln_ids_capped_at_three(tmp_path):
    f = tmp_path / "Cargo.lock"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_MULTIPLE_VULNS)):
            findings = rule.check(f)
    openssl_finding = next(fi for fi in findings if "openssl" in fi.message)
    assert "GHSA-extra-1234-5678" not in openssl_finding.message


def test_osv_no_vulns_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_NO_VULNS)):
            assert rule.check(f) == []


def test_osv_empty_results_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_EMPTY_RESULTS)):
            assert rule.check(f) == []


def test_osv_invalid_json_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock("not json at all")):
            assert rule.check(f) == []


def test_osv_empty_stdout_returns_empty(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock("")):
            assert rule.check(f) == []


def test_osv_fix_message_references_osv_dev(tmp_path):
    f = tmp_path / "go.sum"
    f.write_text("")
    with patch("vigil.rules.deps._find_tool", return_value="/opt/homebrew/bin/osv-scanner"):
        with patch("subprocess.run", return_value=_mock(_OSV_JSON_ONE_VULN)):
            findings = rule.check(f)
    assert "osv.dev" in findings[0].fix
