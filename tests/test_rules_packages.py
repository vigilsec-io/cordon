"""Tests for package audit rule: VGL-PKG001–PKG004."""
import json
import time
import pytest
from pathlib import Path
from unittest.mock import patch
from vigil.rules.packages import PackageAuditRule, _is_stale, _parse_requirements, _parse_package_json, _NOT_FOUND


# ── Parser unit tests ─────────────────────────────────────────────────────────

class TestParsers:
    def test_parse_requirements_pinned(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\nflask==2.3.0\n")
        pkgs = _parse_requirements(f.read_text())
        assert ("requests", "2.31.0", 1) in pkgs
        assert ("flask", "2.3.0", 2) in pkgs

    def test_parse_requirements_ignores_unpinned(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests>=2.0\nflask\n")
        pkgs = _parse_requirements(f.read_text())
        assert pkgs == []

    def test_parse_requirements_ignores_comments(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("# comment\nrequests==2.31.0\n")
        pkgs = _parse_requirements(f.read_text())
        assert len(pkgs) == 1

    def test_parse_package_json(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({
            "dependencies": {"express": "4.18.2"},
            "devDependencies": {"jest": "29.0.0"},
        }))
        pkgs = _parse_package_json(f.read_text())
        names = [p[0] for p in pkgs]
        assert "express" in names
        assert "jest" in names

    def test_parse_package_json_strips_caret(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"express": "^4.18.2"}}))
        pkgs = _parse_package_json(f.read_text())
        assert pkgs[0][1] == "4.18.2"


# ── Staleness helper ──────────────────────────────────────────────────────────

class TestIsStale:
    def test_major_behind(self):
        assert _is_stale("1.0.0", "2.0.0") is True

    def test_more_than_one_minor_behind(self):
        assert _is_stale("1.0.0", "1.2.0") is True

    def test_one_minor_behind_not_stale(self):
        assert _is_stale("1.0.0", "1.1.0") is False

    def test_same_version_not_stale(self):
        assert _is_stale("2.3.1", "2.3.1") is False

    def test_patch_behind_not_stale(self):
        assert _is_stale("2.3.0", "2.3.5") is False

    def test_invalid_version_not_stale(self):
        assert _is_stale("invalid", "2.0.0") is False


# ── Rule: applies_to ──────────────────────────────────────────────────────────

class TestPackageAuditRuleAppliesTo:
    rule = PackageAuditRule()

    def test_applies_to_requirements_txt(self, tmp_path):
        assert self.rule.applies_to(tmp_path / "requirements.txt")

    def test_applies_to_requirements_dev_txt(self, tmp_path):
        assert self.rule.applies_to(tmp_path / "requirements-dev.txt")

    def test_applies_to_package_json(self, tmp_path):
        assert self.rule.applies_to(tmp_path / "package.json")

    def test_does_not_apply_to_node_modules(self, tmp_path):
        assert not self.rule.applies_to(tmp_path / "node_modules" / "pkg" / "package.json")

    def test_does_not_apply_to_py_files(self, tmp_path):
        assert not self.rule.applies_to(tmp_path / "app.py")


# ── Rule: PKG001 known CVE ────────────────────────────────────────────────────

class TestPkgCveFindings:
    rule = PackageAuditRule()

    def test_emits_pkg001_when_osv_returns_vulns(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.0.0\n")

        fake_osv = {"results": [{"vulns": [{"id": "PYSEC-2023-001", "summary": "Critical bug"}]}]}
        fake_pypi = {"info": {"version": "2.31.0"}, "releases": {"2.0.0": [{"upload_time": "2020-01-01T00:00:00"}], "2.31.0": [{"upload_time": "2023-01-01T00:00:00"}]}}

        with patch("vigil.rules.packages._post", return_value=fake_osv), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)

        rule_ids = [fi.rule_id for fi in findings]
        assert "VGL-PKG001" in rule_ids

    def test_emits_pkg002_when_package_not_found(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("totally-fake-hallucinated-pkg==1.0.0\n")

        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=_NOT_FOUND), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)

        rule_ids = [fi.rule_id for fi in findings]
        assert "VGL-PKG002" in rule_ids
        assert any("hallucination" in fi.message for fi in findings)

    def test_emits_pkg003_when_version_stale(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==1.0.0\n")

        fake_pypi = {
            "info": {"version": "3.0.0"},
            "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]},
        }

        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)

        rule_ids = [fi.rule_id for fi in findings]
        assert "VGL-PKG003" in rule_ids

    def test_emits_pkg004_for_new_package(self, tmp_path):
        from datetime import datetime, timedelta
        f = tmp_path / "requirements.txt"
        f.write_text("newpkg==0.1.0\n")

        recent = (datetime.utcnow() - timedelta(days=5)).isoformat()
        fake_pypi = {
            "info": {"version": "0.1.0"},
            "releases": {
                "0.1.0": [{"upload_time": recent}],
            },
        }

        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)

        rule_ids = [fi.rule_id for fi in findings]
        assert "VGL-PKG004" in rule_ids

    def test_no_findings_on_network_error(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")

        with patch("vigil.rules.packages._post", return_value=None), \
             patch("vigil.rules.packages._get", return_value=None), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)

        # Fail-open: network error → no findings (never block user)
        assert findings == []

    def test_empty_requirements_returns_no_findings(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("# just a comment\n")
        findings = self.rule.check(f)
        assert findings == []
