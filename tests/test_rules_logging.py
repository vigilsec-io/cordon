"""Tests for logging secrets rule: VGL-LOG001."""
import pytest
from vigil.rules.logging_secrets import LoggingSecretsRule


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


class TestLoggingSecretsRule:
    rule = LoggingSecretsRule()

    # ── Python logging ────────────────────────────────────────────────────────
    def test_detects_logger_debug_with_password(self, py_file):
        f = py_file("logger.debug(f'Auth attempt: password={password}')\n")
        assert self.rule.check(f)

    def test_detects_logger_info_with_token(self, py_file):
        f = py_file("logger.info('token: %s', token)\n")
        assert self.rule.check(f)

    def test_detects_logging_error_with_api_key(self, py_file):
        f = py_file("logging.error('Failed with api_key=%s', api_key)\n")
        assert self.rule.check(f)

    def test_detects_print_with_secret(self, py_file):
        f = py_file("print(f'secret={secret}')\n")
        assert self.rule.check(f)

    def test_detects_log_full_request_headers(self, py_file):
        f = py_file("logger.debug('Headers: %s', request.headers)\n")
        assert self.rule.check(f)

    def test_detects_log_request_body(self, py_file):
        f = py_file("logger.info('Body: %s', request.body)\n")
        assert self.rule.check(f)

    # ── JavaScript logging ─────────────────────────────────────────────────────
    def test_detects_console_log_with_token(self, js_file):
        f = js_file("console.log('token:', token);\n")
        assert self.rule.check(f)

    def test_detects_console_debug_with_password(self, js_file):
        f = js_file("console.debug('password:', password);\n")
        assert self.rule.check(f)

    def test_detects_console_error_with_api_key(self, js_file):
        f = js_file("console.error('apiKey:', apiKey);\n")
        assert self.rule.check(f)

    # ── Ignores ──────────────────────────────────────────────────────────────
    def test_ignores_log_without_sensitive_name(self, py_file):
        f = py_file("logger.info('Processing %d records', count)\n")
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, py_file):
        f = py_file("# logger.debug('password=%s', password)  — do not do this\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file("logger.info('token: %s', token)  # vigil: ignore\n")
        assert not self.rule.check(f)

    def test_ignores_non_code_file(self, tmp_path):
        f = tmp_path / "notes.txt"
        f.write_text("logger.info('token: %s', token)\n")
        assert not self.rule.applies_to(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file("logger.debug('token=%s', token)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-LOG001"

    def test_finding_mentions_log_files(self, py_file):
        f = py_file("logger.info('api_key=%s', api_key)\n")
        findings = self.rule.check(f)
        assert "log" in findings[0].fix.lower()
