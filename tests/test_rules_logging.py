"""Tests for logging secrets rules: VGL-LOG001–LOG004."""
import pytest
from vigil.rules.logging_secrets import (
    LoggingSecretsRule, ErrorLeakRule, SilentAuthExceptionRule, CrlfLogInjectionRule,
)


@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def web_py_file(tmp_path):
    """Python file with a FastAPI import — VGL-LOG002 only fires in web handlers."""
    def _make(content):
        f = tmp_path / "router.py"
        f.write_text("from fastapi import APIRouter\n" + content)
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

    def test_ignores_sensitive_word_in_plain_string_literal(self, py_file):
        # FP regression: error messages describing what's missing should not fire
        f = py_file('print("ERROR: Gitea token not found in SSM")\n')
        assert not self.rule.check(f)

    def test_ignores_sensitive_word_in_plain_string_literal_logger(self, py_file):
        f = py_file('logger.error("Missing password param — check config")\n')
        assert not self.rule.check(f)

    def test_detects_sensitive_var_in_fstring(self, py_file):
        # f-strings interpolating a variable still fire
        f = py_file('print(f"Auth failed, token={token}")\n')
        assert self.rule.check(f)

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


# ── VGL-LOG002 — Error leak in HTTP response ─────────────────────────────────

class TestErrorLeakRule:
    rule = ErrorLeakRule()

    def test_detects_return_str_exc(self, web_py_file):
        f = web_py_file("    return str(e)\n")
        assert self.rule.check(f)

    def test_detects_return_str_exception_var(self, web_py_file):
        f = web_py_file("    return str(exc)\n")
        assert self.rule.check(f)

    def test_detects_dict_error_str_exc(self, web_py_file):
        f = web_py_file('    return {"error": str(e)}\n')
        assert self.rule.check(f)

    def test_detects_dict_detail_str_err(self, web_py_file):
        f = web_py_file('    return {"detail": str(err)}\n')
        assert self.rule.check(f)

    def test_detects_traceback_format_exc(self, web_py_file):
        f = web_py_file("    tb = traceback.format_exc()\n")
        assert self.rule.check(f)

    def test_detects_traceback_print_exc(self, web_py_file):
        f = web_py_file("    traceback.print_exc()\n")
        assert self.rule.check(f)

    def test_finding_is_high(self, web_py_file):
        f = web_py_file("    return str(e)\n")
        from vigil.rules.base import Severity
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, web_py_file):
        f = web_py_file("    return str(e)\n")
        assert self.rule.check(f)[0].rule_id == "VGL-LOG002"

    def test_fix_mentions_generic_error(self, web_py_file):
        f = web_py_file("    return str(e)\n")
        assert "Internal server error" in self.rule.check(f)[0].fix or "generic" in self.rule.check(f)[0].fix.lower()

    def test_ignores_comment(self, web_py_file):
        f = web_py_file("# return str(e)\n")
        assert not self.rule.check(f)

    # ── Regression: bool-first tuple returns (VGL-LOG002 FP) ─────────────────
    def test_ignores_false_tuple_return(self, web_py_file):
        """return False, str(e)[:80] — internal utility, not HTTP response."""
        f = web_py_file("        return False, str(e)[:80]\n")
        assert not self.rule.check(f)

    def test_ignores_true_tuple_return(self, web_py_file):
        f = web_py_file("        return True, str(exception)\n")
        assert not self.rule.check(f)

    def test_ignores_none_tuple_return(self, web_py_file):
        f = web_py_file("        return None, str(err)\n")
        assert not self.rule.check(f)

    def test_still_detects_plain_str_return(self, web_py_file):
        """Lookahead fix must not suppress bare return str(e)."""
        f = web_py_file("        return str(e)\n")
        assert self.rule.check(f)

    def test_ignores_vigil_ignore(self, web_py_file):
        f = web_py_file("    return str(e)  # vigil: ignore\n")
        assert not self.rule.check(f)

    def test_ignores_safe_str_usage(self, web_py_file):
        f = web_py_file('    return {"count": str(total)}\n')
        assert not self.rule.check(f)

    # ── Regression: non-HTTP files must not fire (VGL-LOG002 FP from qa_runner) ─
    def test_ignores_internal_agent_reason_dict(self, py_file):
        """Agent/script files returning str(e) in dicts for Telegram/logging are not HTTP leaks."""
        f = py_file('        return {"app": app, "skipped": True, "reason": str(e)}\n')
        assert not self.rule.check(f)

    def test_ignores_non_web_str_exc_return(self, py_file):
        """A bare script file with no web framework import must not trigger."""
        f = py_file("    return str(e)\n")
        assert not self.rule.check(f)


# ── VGL-LOG003 — Silent exception in auth context ────────────────────────────

class TestSilentAuthExceptionRule:
    rule = SilentAuthExceptionRule()

    def test_detects_except_pass_in_auth_file(self, tmp_path):
        f = tmp_path / "auth.py"
        f.write_text(
            "def authenticate(user, password):\n"
            "    try:\n"
            "        verify_token(token)\n"
            "    except Exception:\n"
            "        pass\n"
        )
        assert self.rule.check(f)

    def test_detects_bare_except_pass_near_login(self, py_file):
        f = py_file(
            "def login(username, password):\n"
            "    try:\n"
            "        check_password(password)\n"
            "    except:\n"
            "        pass\n"
        )
        assert self.rule.check(f)

    def test_ignores_except_pass_without_security_context(self, py_file):
        f = py_file(
            "def read_file(path):\n"
            "    try:\n"
            "        return open(path).read()\n"
            "    except:\n"
            "        pass\n"
        )
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "verify.py"
        f.write_text(
            "def verify_token(jwt):\n"
            "    try:\n"
            "        decode(jwt)\n"
            "    except:\n"
            "        pass\n"
        )
        assert self.rule.check(f)[0].rule_id == "VGL-LOG003"

    def test_fix_mentions_logging(self, tmp_path):
        f = tmp_path / "session.py"
        f.write_text(
            "def authenticate(user, password):\n"
            "    try:\n"
            "        check_credential(password)\n"
            "    except:\n"
            "        pass\n"
        )
        findings = self.rule.check(f)
        assert "log" in findings[0].fix.lower()

    def test_ignores_vigil_ignore(self, tmp_path):
        f = tmp_path / "auth_helper.py"
        f.write_text(
            "def authenticate(user, token):\n"
            "    try:\n"
            "        check(token)\n"
            "    except:  # vigil: ignore\n"
            "        pass\n"
        )
        assert not self.rule.check(f)


# ── VGL-LOG004 — CRLF injection via user input ───────────────────────────────

class TestCrlfLogInjectionRule:
    rule = CrlfLogInjectionRule()

    def test_detects_logger_with_request_args(self, py_file):
        f = py_file("logger.info('User: %s', request.args.get('name'))\n")
        assert self.rule.check(f)

    def test_detects_logger_with_query_params(self, py_file):
        f = py_file("logger.debug('Query: %s', request.query_params['q'])\n")
        assert self.rule.check(f)

    def test_detects_print_with_request_path(self, py_file):
        f = py_file("print('Accessed:', request.path)\n")
        assert self.rule.check(f)

    def test_detects_console_log_with_query_string(self, js_file):
        f = js_file("console.log('Query:', request.GET['search']);\n")
        assert self.rule.check(f)

    def test_finding_has_correct_rule_id(self, py_file):
        f = py_file("logger.info('search=%s', request.args['q'])\n")
        assert self.rule.check(f)[0].rule_id == "VGL-LOG004"

    def test_fix_mentions_strip(self, py_file):
        f = py_file("logger.info('x=%s', request.GET['x'])\n")
        findings = self.rule.check(f)
        assert "replace" in findings[0].fix or "strip" in findings[0].fix

    def test_ignores_log_without_user_input(self, py_file):
        f = py_file("logger.info('Processing %d items', count)\n")
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file("# logger.info('name=%s', request.args.get('name'))\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file("logger.info('q=%s', request.args['q'])  # vigil: ignore\n")
        assert not self.rule.check(f)
