"""Tests for VGL-PY001 — debug bypass without env guard."""
import pytest
from vigil.rules.python import DebugBypassRule
from vigil.rules.base import Severity


@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make


class TestDebugBypassRule:
    rule = DebugBypassRule()

    # ── env-var bypass patterns ───────────────────────────────────────────

    def test_detects_environ_get_skip_auth(self, py_file):
        f = py_file('if os.environ.get("SKIP_AUTH"):\n    return user\n')
        assert self.rule.check(f)

    def test_detects_getenv_bypass_auth(self, py_file):
        f = py_file('skip = os.getenv("BYPASS_AUTH")\n')
        assert self.rule.check(f)

    def test_detects_environ_subscript_disable_auth(self, py_file):
        f = py_file('if os.environ["DISABLE_AUTH"]:\n    pass\n')
        assert self.rule.check(f)

    def test_detects_environ_get_no_auth(self, py_file):
        f = py_file('auth_skip = os.environ.get("NO_AUTH")\n')
        assert self.rule.check(f)

    # ── hardcoded boolean assignments ────────────────────────────────────

    def test_detects_skip_auth_true(self, py_file):
        f = py_file('SKIP_AUTH = True\n')
        assert self.rule.check(f)

    def test_detects_bypass_auth_true_lowercase(self, py_file):
        f = py_file('bypass_auth = True\n')
        assert self.rule.check(f)

    def test_detects_require_auth_false(self, py_file):
        f = py_file('REQUIRE_AUTH = False\n')
        assert self.rule.check(f)

    def test_detects_auth_enabled_false(self, py_file):
        f = py_file('AUTH_ENABLED = False\n')
        assert self.rule.check(f)

    def test_detects_enforce_auth_false(self, py_file):
        f = py_file('ENFORCE_AUTH = False\n')
        assert self.rule.check(f)

    # ── safe patterns / false-positive guards ────────────────────────────

    def test_ignores_skip_auth_false(self, py_file):
        """SKIP_AUTH = False means auth IS enforced — not a bypass."""
        f = py_file('SKIP_AUTH = False\n')
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, py_file):
        f = py_file('# SKIP_AUTH = True  # never do this\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file('SKIP_AUTH = True  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_ignores_non_python_file(self, tmp_path):
        """Extension check is the engine's job via applies_to, not check()."""
        f = tmp_path / "config.js"
        assert not self.rule.applies_to(f)

    # ── finding metadata ─────────────────────────────────────────────────

    def test_finding_rule_id(self, py_file):
        f = py_file('SKIP_AUTH = True\n')
        findings = self.rule.check(f)
        assert findings[0].rule_id == "VGL-PY001"

    def test_finding_severity_is_high(self, py_file):
        f = py_file('REQUIRE_AUTH = False\n')
        findings = self.rule.check(f)
        assert findings[0].severity == Severity.HIGH

    def test_finding_line_number(self, py_file):
        f = py_file('# safe line\nSKIP_AUTH = True\n')
        findings = self.rule.check(f)
        assert findings[0].line == 2

    def test_multiple_findings_in_one_file(self, py_file):
        f = py_file(
            'SKIP_AUTH = True\n'
            'REQUIRE_AUTH = False\n'
        )
        assert len(self.rule.check(f)) == 2

    def test_applies_to_py_extension(self, tmp_path):
        assert self.rule.applies_to(tmp_path / "main.py")

    def test_does_not_apply_to_yaml(self, tmp_path):
        assert not self.rule.applies_to(tmp_path / "config.yaml")
