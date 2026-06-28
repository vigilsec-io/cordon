"""Tests for web security rules: SSRF, SQL injection, CORS, SSL."""
import pytest
from pathlib import Path
from vigil.rules.web import (
    SsrfRule, SqlInjectionFstringRule, SqlOrmRawRule,
    CorsWildcardRule, SslVerifyDisabledRule,
)


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "app.py"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def yml_file(tmp_path):
    def _make(content):
        f = tmp_path / "config.yml"
        f.write_text(content)
        return f
    return _make


# ── VGL-SSRF001 ───────────────────────────────────────────────────────────────

class TestSsrfRule:
    rule = SsrfRule()

    def test_detects_requests_get_with_request_url(self, py_file):
        f = py_file("response = requests.get(request.args.get('url'))\n")
        assert self.rule.check(f)

    def test_detects_requests_post_with_user_url(self, py_file):
        f = py_file("resp = requests.post(user_url, json=data)\n")
        assert self.rule.check(f)

    def test_detects_httpx_with_callback_url(self, py_file):
        f = py_file("r = httpx.get(callback_url)\n")
        assert self.rule.check(f)

    def test_ignores_literal_url(self, py_file):
        f = py_file('resp = requests.get("https://api.example.com/data")\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file("# requests.get(request.url) — example\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, py_file):
        f = py_file("resp = requests.get(redirect_url)  # vigil: ignore\n")
        assert not self.rule.check(f)


# ── VGL-SQL001 ────────────────────────────────────────────────────────────────

class TestSqlInjectionFstringRule:
    rule = SqlInjectionFstringRule()

    def test_detects_fstring_select(self, py_file):
        f = py_file('query = f"SELECT * FROM users WHERE id = {user_id}"\n')
        assert self.rule.check(f)

    def test_detects_fstring_insert(self, py_file):
        f = py_file('q = f"INSERT INTO logs VALUES ({name}, {val})"\n')
        assert self.rule.check(f)

    def test_detects_string_concat(self, py_file):
        f = py_file('sql = "SELECT * FROM users WHERE name = " + username\n')
        assert self.rule.check(f)

    def test_detects_percent_formatting(self, py_file):
        f = py_file('cursor.execute("SELECT * FROM t WHERE id = %s" % uid)\n')
        assert self.rule.check(f)

    def test_ignores_parameterized(self, py_file):
        f = py_file('cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))\n')
        assert not self.rule.check(f)

    def test_ignores_safe_fstring(self, py_file):
        f = py_file('label = f"Processing {count} records"\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# f"SELECT * FROM users WHERE id = {user_id}"\n')
        assert not self.rule.check(f)


# ── VGL-SQL002 ────────────────────────────────────────────────────────────────

class TestSqlOrmRawRule:
    rule = SqlOrmRawRule()

    def test_detects_orm_raw_fstring(self, py_file):
        f = py_file('results = User.objects.raw(f"SELECT * FROM users WHERE id={uid}")\n')
        assert self.rule.check(f)

    def test_detects_execute_fstring(self, py_file):
        f = py_file('db.execute(f"UPDATE users SET name={name} WHERE id={uid}")\n')
        assert self.rule.check(f)

    def test_ignores_raw_with_literal(self, py_file):
        f = py_file('User.objects.raw("SELECT * FROM users WHERE id=%s", [uid])\n')
        assert not self.rule.check(f)


# ── VGL-CORS001 ───────────────────────────────────────────────────────────────

class TestCorsWildcardRule:
    rule = CorsWildcardRule()

    def test_detects_fastapi_cors_wildcard(self, py_file):
        f = py_file('app.add_middleware(CORSMiddleware, allow_origins=["*"])\n')
        assert self.rule.check(f)

    def test_detects_django_cors_allow_all(self, py_file):
        f = py_file("CORS_ORIGIN_ALLOW_ALL = True\n")
        assert self.rule.check(f)

    def test_detects_http_header(self, yml_file):
        f = yml_file("add_header Access-Control-Allow-Origin '*';\n")
        assert self.rule.check(f)

    def test_ignores_specific_origin(self, py_file):
        f = py_file('app.add_middleware(CORSMiddleware, allow_origins=["https://app.example.com"])\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# allow_origins=["*"]  — do not use in production\n')
        assert not self.rule.check(f)


# ── VGL-SSL001 ────────────────────────────────────────────────────────────────

class TestSslVerifyDisabledRule:
    rule = SslVerifyDisabledRule()

    def test_detects_verify_false(self, py_file):
        f = py_file('resp = requests.get(url, verify=False)\n')
        assert self.rule.check(f)

    def test_detects_cert_none(self, py_file):
        f = py_file('ctx.verify_mode = ssl.CERT_NONE\n')
        assert self.rule.check(f)

    def test_detects_unverified_context(self, py_file):
        f = py_file('ctx = ssl._create_unverified_context()\n')
        assert self.rule.check(f)

    def test_detects_disable_warnings(self, py_file):
        f = py_file('urllib3.disable_warnings()\n')
        assert self.rule.check(f)

    def test_ignores_verify_true(self, py_file):
        f = py_file('resp = requests.get(url, verify=True)\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, py_file):
        f = py_file('# verify=False is insecure — do not use\n')
        assert not self.rule.check(f)
