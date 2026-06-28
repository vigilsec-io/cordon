"""Tests for row-level security rules: VGL-RLS001, VGL-RLS002."""
import pytest
from vigil.rules.rls import RlsDisabledRule, MissingTenantFilterRule


@pytest.fixture
def sql_file(tmp_path):
    def _make(content):
        f = tmp_path / "migration.sql"
        f.write_text(content)
        return f
    return _make

@pytest.fixture
def py_file(tmp_path):
    def _make(content):
        f = tmp_path / "views.py"
        f.write_text(content)
        return f
    return _make


# ── VGL-RLS001 ────────────────────────────────────────────────────────────────

class TestRlsDisabledRule:
    rule = RlsDisabledRule()

    def test_detects_disable_rls_sql(self, sql_file):
        f = sql_file("ALTER TABLE orders DISABLE ROW LEVEL SECURITY;\n")
        assert self.rule.check(f)

    def test_detects_set_row_security_off(self, sql_file):
        f = sql_file("SET row_security = off;\n")
        assert self.rule.check(f)

    def test_detects_disable_rls_in_python_migration(self, py_file):
        f = py_file('op.execute("ALTER TABLE t DISABLE ROW LEVEL SECURITY")\n')
        assert self.rule.check(f)

    def test_detects_set_row_security_false_in_python(self, py_file):
        f = py_file('conn.execute("SET row_security = off")\n')
        assert self.rule.check(f)

    def test_ignores_enable_rls(self, sql_file):
        f = sql_file("ALTER TABLE orders ENABLE ROW LEVEL SECURITY;\n")
        assert not self.rule.check(f)

    def test_ignores_sql_comment(self, sql_file):
        f = sql_file("-- DISABLE ROW LEVEL SECURITY  — do not use\n")
        assert not self.rule.check(f)

    def test_ignores_python_comment(self, py_file):
        f = py_file('# SET row_security = off\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, sql_file):
        f = sql_file("SET row_security = off;  -- vigil: ignore\n")
        assert not self.rule.check(f)

    def test_finding_is_critical(self, sql_file):
        from vigil.rules.base import Severity
        f = sql_file("ALTER TABLE t DISABLE ROW LEVEL SECURITY;\n")
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, sql_file):
        f = sql_file("SET row_security = off;\n")
        assert self.rule.check(f)[0].rule_id == "VGL-RLS001"


# ── VGL-RLS002 ────────────────────────────────────────────────────────────────

class TestMissingTenantFilterRule:
    rule = MissingTenantFilterRule()

    def _mt_file(self, tmp_path, content):
        # Include tenant context so the rule activates
        f = tmp_path / "views.py"
        f.write_text("# multi-tenant: tenant_id filtering required\n" + content)
        return f

    def test_detects_bare_objects_all(self, tmp_path):
        f = self._mt_file(tmp_path, "orders = Order.objects.all()\n")
        assert self.rule.check(f)

    def test_detects_get_by_id_only(self, tmp_path):
        f = self._mt_file(tmp_path, "order = Order.objects.get(id=pk)\n")
        assert self.rule.check(f)

    def test_ignores_all_when_no_mt_context(self, py_file):
        # No tenant/org/account signal in file
        f = py_file("users = User.objects.all()\n")
        assert not self.rule.check(f)

    def test_ignores_get_with_user_scope(self, tmp_path):
        f = self._mt_file(tmp_path, "order = Order.objects.get(id=pk, user=request.user)\n")
        assert not self.rule.check(f)

    def test_ignores_get_with_tenant_scope(self, tmp_path):
        f = self._mt_file(tmp_path, "order = Order.objects.get(id=pk, tenant=request.tenant)\n")
        assert not self.rule.check(f)

    def test_ignores_comment(self, tmp_path):
        f = self._mt_file(tmp_path, "# Order.objects.all()  — use filter(tenant=...) instead\n")
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, tmp_path):
        f = self._mt_file(tmp_path, "orders = Order.objects.all()  # vigil: ignore\n")
        assert not self.rule.check(f)

    def test_finding_message_mentions_idor(self, tmp_path):
        f = self._mt_file(tmp_path, "order = Order.objects.get(id=pk)\n")
        findings = self.rule.check(f)
        assert any("IDOR" in fi.message or "IDOR" in fi.fix for fi in findings)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = self._mt_file(tmp_path, "orders = Order.objects.all()\n")
        assert self.rule.check(f)[0].rule_id == "VGL-RLS002"
