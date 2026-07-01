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

        recent = (datetime.now() - timedelta(days=5)).isoformat()
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

    def test_pkg001_severity_is_critical(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.0.0\n")
        fake_osv = {"results": [{"vulns": [{"id": "PYSEC-2023-001", "summary": "bug"}]}]}
        fake_pypi = {"info": {"version": "2.0.0"}, "releases": {"2.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}}
        with patch("vigil.rules.packages._post", return_value=fake_osv), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        pkg001 = [fi for fi in findings if fi.rule_id == "VGL-PKG001"]
        assert pkg001[0].severity.value == "CRITICAL"

    def test_pkg002_severity_is_critical(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("fakepkg==1.0.0\n")
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=_NOT_FOUND), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        pkg002 = [fi for fi in findings if fi.rule_id == "VGL-PKG002"]
        assert pkg002[0].severity.value == "CRITICAL"

    def test_pkg003_severity_is_high(self, tmp_path):
        f = tmp_path / "requirements.txt"
        f.write_text("requests==1.0.0\n")
        fake_pypi = {"info": {"version": "3.0.0"}, "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}}
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        pkg003 = [fi for fi in findings if fi.rule_id == "VGL-PKG003"]
        assert pkg003[0].severity.value == "HIGH"

    def test_pkg004_severity_is_high(self, tmp_path):
        from datetime import datetime, timedelta
        f = tmp_path / "requirements.txt"
        f.write_text("newpkg==0.1.0\n")
        recent = (datetime.now() - timedelta(days=5)).isoformat()
        fake_pypi = {"info": {"version": "0.1.0"}, "releases": {"0.1.0": [{"upload_time": recent}]}}
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        pkg004 = [fi for fi in findings if fi.rule_id == "VGL-PKG004"]
        assert pkg004[0].severity.value == "HIGH"

    def test_pkg004_not_emitted_for_established_package(self, tmp_path):
        """Packages with many releases should not trigger PKG004."""
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        fake_pypi = {
            "info": {"version": "2.31.0"},
            "releases": {
                f"2.{i}.0": [{"upload_time": "2020-01-01T00:00:00"}] for i in range(20)
            },
        }
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert not any(fi.rule_id == "VGL-PKG004" for fi in findings)

    def test_pkg003_not_emitted_for_one_minor_behind(self, tmp_path):
        """One minor version behind is not flagged as stale."""
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.0.0\n")
        fake_pypi = {
            "info": {"version": "2.1.0"},
            "releases": {"2.0.0": [{"upload_time": "2020-01-01T00:00:00"}]},
        }
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert not any(fi.rule_id == "VGL-PKG003" for fi in findings)

    def test_multiple_packages_all_checked(self, tmp_path):
        """Every pinned package in the file is checked independently."""
        f = tmp_path / "requirements.txt"
        f.write_text("pkg-a==1.0.0\npkg-b==2.0.0\n")
        fake_pypi = {"info": {"version": "1.0.0"}, "releases": {"1.0.0": [{"upload_time": "2020-01-01T00:00:00"}]}}
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}, {"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        # Both packages were processed (no crash) — test passes if no exception


class TestPackageAuditNpm:
    """npm (package.json) ecosystem checks."""
    rule = PackageAuditRule()

    def test_emits_pkg001_for_npm_cve(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"express": "4.17.0"}}))
        fake_osv = {"results": [{"vulns": [{"id": "GHSA-abc-123", "summary": "XSS bug"}]}]}
        fake_npm = {"version": "4.18.2"}
        with patch("vigil.rules.packages._post", return_value=fake_osv), \
             patch("vigil.rules.packages._get", return_value=fake_npm), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert any(fi.rule_id == "VGL-PKG001" for fi in findings)
        assert any("GHSA-abc-123" in fi.message for fi in findings)

    def test_emits_pkg002_for_npm_not_found(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"hallucinated-npm-pkg": "1.0.0"}}))
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=_NOT_FOUND), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert any(fi.rule_id == "VGL-PKG002" for fi in findings)

    def test_emits_pkg003_for_npm_stale(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"express": "2.0.0"}}))
        fake_npm = {"version": "5.0.0"}
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_npm), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert any(fi.rule_id == "VGL-PKG003" for fi in findings)

    def test_npm_fail_open_on_network_error(self, tmp_path):
        f = tmp_path / "package.json"
        f.write_text(json.dumps({"dependencies": {"react": "18.0.0"}}))
        with patch("vigil.rules.packages._post", return_value=None), \
             patch("vigil.rules.packages._get", return_value=None), \
             patch("vigil.rules.packages._load_cache", return_value={}), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        assert findings == []


class TestPackageAuditCache:
    """Cache hits prevent redundant HTTP calls."""
    rule = PackageAuditRule()

    def test_cache_hit_skips_osv_call(self, tmp_path):
        """A warm cache for vuln: key means _post is never called."""
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        warm_cache = {
            "vuln:PyPI:requests:2.31.0": {"v": [], "ts": time.time()},
            "info:PyPI:requests": {"v": {"info": {"version": "2.31.0"}, "releases": {"2.31.0": [{"upload_time": "2020-01-01T00:00:00"}]}}, "ts": time.time()},
        }
        with patch("vigil.rules.packages._post") as mock_post, \
             patch("vigil.rules.packages._load_cache", return_value=warm_cache), \
             patch("vigil.rules.packages._save_cache"):
            self.rule.check(f)
        mock_post.assert_not_called()

    def test_cache_hit_skips_registry_call(self, tmp_path):
        """A warm cache for info: key means _get is never called."""
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        warm_cache = {
            "vuln:PyPI:requests:2.31.0": {"v": [], "ts": time.time()},
            "info:PyPI:requests": {"v": {"info": {"version": "2.31.0"}, "releases": {"2.31.0": [{"upload_time": "2020-01-01T00:00:00"}]}}, "ts": time.time()},
        }
        with patch("vigil.rules.packages._get") as mock_get, \
             patch("vigil.rules.packages._load_cache", return_value=warm_cache), \
             patch("vigil.rules.packages._save_cache"):
            self.rule.check(f)
        mock_get.assert_not_called()

    def test_expired_cache_refetches(self, tmp_path):
        """An expired cache entry (> 24h old) is treated as a miss — _get is called."""
        f = tmp_path / "requirements.txt"
        f.write_text("requests==2.31.0\n")
        stale_ts = time.time() - 90_000   # 25h ago — expired
        stale_cache = {
            "vuln:PyPI:requests:2.31.0": {"v": [], "ts": stale_ts},
        }
        fake_pypi = {"info": {"version": "2.31.0"}, "releases": {"2.31.0": [{"upload_time": "2020-01-01T00:00:00"}]}}
        with patch("vigil.rules.packages._post", return_value={"results": [{"vulns": []}]}), \
             patch("vigil.rules.packages._get", return_value=fake_pypi) as mock_get, \
             patch("vigil.rules.packages._load_cache", return_value=stale_cache), \
             patch("vigil.rules.packages._save_cache"):
            self.rule.check(f)
        mock_get.assert_called()

    def test_not_found_cached_as_false(self, tmp_path):
        """A confirmed-404 result is cached as False and re-used without network call."""
        f = tmp_path / "requirements.txt"
        f.write_text("fakepkg==1.0.0\n")
        warm_cache = {
            "vuln:PyPI:fakepkg:1.0.0": {"v": [], "ts": time.time()},
            "info:PyPI:fakepkg": {"v": False, "ts": time.time()},  # cached not-found
        }
        with patch("vigil.rules.packages._get") as mock_get, \
             patch("vigil.rules.packages._load_cache", return_value=warm_cache), \
             patch("vigil.rules.packages._save_cache"):
            findings = self.rule.check(f)
        mock_get.assert_not_called()
        assert any(fi.rule_id == "VGL-PKG002" for fi in findings)
