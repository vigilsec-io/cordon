"""Tests for JS/TS security rules: VGL-JS001, VGL-JS004."""
import pytest
from vigil.rules.js_security import ProcessEnvFallbackRule, JsEvalNewFunctionRule


@pytest.fixture
def js_file(tmp_path):
    def _make(content, ext=".js"):
        f = tmp_path / f"app{ext}"
        f.write_text(content)
        return f
    return _make


# ── VGL-JS001 — process.env fallback ──────────────────────────────────────────

class TestProcessEnvFallbackRule:
    rule = ProcessEnvFallbackRule()

    def test_detects_or_fallback_api_key(self, js_file):
        f = js_file('const key = process.env.API_KEY || "hardcoded-key-123";\n')
        assert self.rule.check(f)

    def test_detects_nullish_fallback_secret(self, js_file):
        f = js_file('const secret = process.env.SECRET ?? "fallback-secret";\n')
        assert self.rule.check(f)

    def test_detects_token_fallback(self, js_file):
        f = js_file('const token = process.env.AUTH_TOKEN || "dev-token-abc";\n')
        assert self.rule.check(f)

    def test_detects_password_fallback(self, js_file):
        f = js_file('const pw = process.env.DB_PASSWORD || "localpassword";\n')
        assert self.rule.check(f)

    def test_detects_in_tsx(self, js_file):
        f = js_file('const key = process.env.REACT_APP_API_KEY || "fallback";\n', ext=".tsx")
        assert self.rule.check(f)

    def test_ignores_non_sensitive_env_var(self, js_file):
        # PORT, HOST, NODE_ENV — not security-sensitive names
        f = js_file('const port = process.env.PORT || "3000";\n')
        assert not self.rule.check(f)

    def test_ignores_non_sensitive_name_base_url(self, js_file):
        f = js_file('const url = process.env.BASE_URL || "http://localhost";\n')
        assert not self.rule.check(f)

    def test_ignores_undefined_fallback(self, js_file):
        f = js_file('const key = process.env.API_KEY || undefined;\n')
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, js_file):
        f = js_file('// const key = process.env.API_KEY || "hardcoded";\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, js_file):
        f = js_file('const k = process.env.SECRET || "fallback";  // vigil: ignore\n')
        assert not self.rule.check(f)

    def test_ignores_non_js_file(self, tmp_path):
        f = tmp_path / "config.py"
        assert not self.rule.applies_to(f)

    def test_finding_names_the_env_var(self, js_file):
        f = js_file('const key = process.env.API_KEY || "hardcoded-key";\n')
        findings = self.rule.check(f)
        assert "API_KEY" in findings[0].message

    def test_finding_has_correct_rule_id(self, js_file):
        f = js_file('const k = process.env.SECRET || "val";\n')
        assert self.rule.check(f)[0].rule_id == "VGL-JS001"


# ── VGL-JS004 — eval / new Function ───────────────────────────────────────────

class TestJsEvalNewFunctionRule:
    rule = JsEvalNewFunctionRule()

    def test_detects_new_function(self, js_file):
        f = js_file('const fn = new Function("return 1 + 1");\n')
        assert self.rule.check(f)

    def test_detects_new_function_with_variable(self, js_file):
        f = js_file('const fn = new Function("x", userCode);\n')
        assert self.rule.check(f)

    def test_detects_eval_with_variable(self, js_file):
        f = js_file('eval(userInput);\n')
        assert self.rule.check(f)

    def test_detects_eval_with_expression(self, js_file):
        f = js_file('eval(data.code);\n')
        assert self.rule.check(f)

    def test_detects_in_ts(self, js_file):
        f = js_file('const result = eval(template);\n', ext=".ts")
        assert self.rule.check(f)

    def test_ignores_eval_with_string_literal(self, js_file):
        # eval("static string") is still bad practice but lower risk — leave to linters
        f = js_file('eval("console.log(1)");\n')
        assert not self.rule.check(f)

    def test_ignores_eval_with_template_literal_open(self, js_file):
        f = js_file('eval(`console.log("hi")`);\n')
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, js_file):
        f = js_file('// eval(userInput); — never do this\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, js_file):
        f = js_file('eval(code);  // vigil: ignore\n')
        assert not self.rule.check(f)

    def test_ignores_non_js_file(self, tmp_path):
        f = tmp_path / "app.py"
        assert not self.rule.applies_to(f)

    def test_new_function_finding_has_correct_rule_id(self, js_file):
        f = js_file('new Function("return 1");\n')
        assert self.rule.check(f)[0].rule_id == "VGL-JS004"

    def test_eval_finding_has_correct_rule_id(self, js_file):
        f = js_file('eval(x);\n')
        assert self.rule.check(f)[0].rule_id == "VGL-JS004"
