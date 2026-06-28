"""Tests for auth security rules: VGL-AUTH001–004."""
import pytest
from vigil.rules.auth import (
    JwtAlgorithmNoneRule,
    JwtVerifyDisabledRule,
    WeakSecretKeyRule,
    DebugModeEnabledRule,
)


@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make


# ── VGL-AUTH001 — JWT algorithm=none ─────────────────────────────────────────

class TestJwtAlgorithmNoneRule:
    rule = JwtAlgorithmNoneRule()

    def test_detects_algorithms_none_list(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["none"])\n')
        assert self.rule.check(f)

    def test_detects_algorithm_none_single(self, py_file):
        f = py_file('jwt.decode(token, key, algorithm="none")\n')
        assert self.rule.check(f)

    def test_detects_uppercase_none(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["None"])\n')
        assert self.rule.check(f)

    def test_ignores_hs256(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["HS256"])\n')
        assert not self.rule.check(f)

    def test_ignores_rs256(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["RS256"])\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# algorithms=["none"]  — never use this\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["none"])  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_finding_is_critical(self, py_file):
        from vigil.rules.base import Severity
        f = py_file('jwt.decode(token, key, algorithms=["none"])\n')
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file('jwt.decode(token, key, algorithms=["none"])\n')
        assert self.rule.check(f)[0].rule_id == "VGL-AUTH001"


# ── VGL-AUTH002 — JWT verify_signature disabled ───────────────────────────────

class TestJwtVerifyDisabledRule:
    rule = JwtVerifyDisabledRule()

    def test_detects_verify_signature_false(self, py_file):
        f = py_file('jwt.decode(token, options={"verify_signature": False})\n')
        assert self.rule.check(f)

    def test_detects_verify_signature_false_key_variants(self, py_file):
        f = py_file('decoded = jwt.decode(t, key, options={"verify_signature": False, "verify_exp": False})\n')
        assert self.rule.check(f)

    def test_ignores_verify_signature_true(self, py_file):
        f = py_file('jwt.decode(token, key, options={"verify_exp": True})\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# options={"verify_signature": False}  — never do this in prod\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file('jwt.decode(token, options={"verify_signature": False})\n')
        assert self.rule.check(f)[0].rule_id == "VGL-AUTH002"


# ── VGL-AUTH003 — Weak secret key ─────────────────────────────────────────────

class TestWeakSecretKeyRule:
    rule = WeakSecretKeyRule()

    def test_detects_secret_key_changeme(self, py_file):
        f = py_file('SECRET_KEY = "changeme"\n')
        assert self.rule.check(f)

    def test_detects_secret_key_debug(self, py_file):
        f = py_file('SECRET_KEY = "debug"\n')
        assert self.rule.check(f)

    def test_detects_app_secret_key_dev(self, py_file):
        f = py_file('app.secret_key = "dev"\n')
        assert self.rule.check(f)

    def test_detects_weak_secret_value(self, py_file):
        f = py_file('SECRET_KEY = "secret"\n')
        assert self.rule.check(f)

    def test_detects_short_secret_key(self, py_file):
        f = py_file('SECRET_KEY = "tooshort"\n')
        assert self.rule.check(f)

    def test_ignores_strong_secret(self, py_file):
        f = py_file('SECRET_KEY = os.environ["SECRET_KEY"]\n')
        assert not self.rule.check(f)

    def test_ignores_ssm_reference(self, py_file):
        f = py_file('SECRET_KEY = get_parameter("/app/secret_key")\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# SECRET_KEY = "changeme"  — replace before deploy\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file('SECRET_KEY = "debug"\n')
        assert self.rule.check(f)[0].rule_id == "VGL-AUTH003"


# ── VGL-AUTH004 — Debug mode enabled ─────────────────────────────────────────

class TestDebugModeEnabledRule:
    rule = DebugModeEnabledRule()

    def test_detects_flask_debug_true(self, py_file):
        f = py_file('app.run(host="0.0.0.0", debug=True)\n')
        assert self.rule.check(f)

    def test_detects_django_debug_true(self, py_file):
        f = py_file('DEBUG = True\n')
        assert self.rule.check(f)

    def test_ignores_flask_debug_false(self, py_file):
        f = py_file('app.run(host="0.0.0.0", debug=False)\n')
        assert not self.rule.check(f)

    def test_ignores_django_debug_false(self, py_file):
        f = py_file('DEBUG = False\n')
        assert not self.rule.check(f)

    def test_ignores_debug_env_var(self, py_file):
        f = py_file('DEBUG = os.getenv("DEBUG", "false") == "true"\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# DEBUG = True  — only for local dev\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file('DEBUG = True  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file('DEBUG = True\n')
        assert self.rule.check(f)[0].rule_id == "VGL-AUTH004"
