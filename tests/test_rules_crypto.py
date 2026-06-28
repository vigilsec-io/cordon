"""Tests for cryptographic weakness rules: VGL-RAND001."""
import pytest
from vigil.rules.crypto import WeakRandomnessRule


@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make


@pytest.fixture
def js_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.js"
        f.write_text(content)
        return f
    return _make


class TestWeakRandomnessRule:
    rule = WeakRandomnessRule()

    def test_detects_random_for_password(self, py_file):
        f = py_file("password = random.randint(100000, 999999)\n")
        assert self.rule.check(f)

    def test_detects_random_for_token(self, py_file):
        f = py_file("token = random.choice(chars)\n")
        assert self.rule.check(f)

    def test_detects_random_for_otp(self, py_file):
        f = py_file("otp = random.randrange(100000, 999999)\n")
        assert self.rule.check(f)

    def test_detects_random_for_api_key(self, py_file):
        f = py_file("api_key = ''.join(random.choice(string.ascii_letters) for _ in range(32))\n")
        assert self.rule.check(f)

    def test_detects_random_for_csrf(self, py_file):
        f = py_file("csrf = random.random()\n")
        assert self.rule.check(f)

    def test_detects_random_for_session_id(self, py_file):
        f = py_file("session_id = str(random.randint(0, 2**64))\n")
        assert self.rule.check(f)

    def test_ignores_random_for_non_security_name(self, py_file):
        f = py_file("delay = random.randint(1, 10)\n")
        assert not self.rule.check(f)

    def test_ignores_secrets_module(self, py_file):
        f = py_file("token = secrets.token_hex(32)\n")
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, py_file):
        f = py_file("# password = random.randint(0, 999999) — don't do this\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file("token = random.choice(chars)  # vigil: ignore\n")
        assert not self.rule.check(f)

    def test_ignores_non_code_file(self, tmp_path):
        f = tmp_path / "note.txt"
        f.write_text("password = random.randint(0, 999999)\n")
        assert not self.rule.applies_to(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file("token = random.randint(0, 1000000)\n")
        findings = self.rule.check(f)
        assert findings[0].rule_id == "VGL-RAND001"

    def test_finding_suggests_secrets_module(self, py_file):
        f = py_file("password = random.randint(0, 999999)\n")
        findings = self.rule.check(f)
        assert "secrets" in findings[0].fix
