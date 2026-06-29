import pytest
from pathlib import Path
from vigil.rules.secrets import (
    AwsAccessKeyRule, HardcodedPasswordRule, HardcodedApiKeyRule,
    EvalInjectionRule, ShellTrueRule, OsSystemRule, CredentialUrlRule,
    InsecureConfigDefaultRule,
)
from vigil.rules.base import Severity


def test_aws_key_detected(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = AwsAccessKeyRule().check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].line == 1


def test_hardcoded_password_detected(tmp_path):
    f = tmp_path / "settings.py"
    f.write_text('DB_PASSWORD = "mysecretpass123"\n')
    findings = HardcodedPasswordRule().check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_hardcoded_api_key_detected(tmp_path):
    f = tmp_path / "app.py"
    f.write_text('api_key = "sk-thisis-a-fake-key-1234567890"\n')
    findings = HardcodedApiKeyRule().check(f)
    assert len(findings) == 1


def test_eval_injection_detected(tmp_path):
    f = tmp_path / "app.py"
    f.write_text("result = eval(user_input)\n")
    findings = EvalInjectionRule().check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_shell_true_detected(tmp_path):
    f = tmp_path / "runner.py"
    f.write_text("subprocess.run(cmd, shell=True)\n")
    findings = ShellTrueRule().check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_shell_true_in_docstring_not_flagged(tmp_path):
    """Regression: 'subprocess shell=True' in a docstring should not fire VGL-I002."""
    f = tmp_path / "agent.py"
    f.write_text(
        '"""\nCovers the gap no other tool fills: subprocess shell=True, and known dep CVEs.\n"""\n'
    )
    assert ShellTrueRule().check(f) == []


def test_shell_true_in_comment_not_flagged(tmp_path):
    """Comment-only lines should not trigger VGL-I002."""
    f = tmp_path / "util.py"
    f.write_text("# subprocess.run(cmd, shell=True) — do not use this pattern\n")
    assert ShellTrueRule().check(f) == []


def test_os_system_detected(tmp_path):
    f = tmp_path / "util.py"
    f.write_text("os.system('ls')\n")
    findings = OsSystemRule().check(f)
    assert len(findings) == 1


def test_env_var_reference_not_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('api_key = os.environ["MY_API_KEY"]\n')
    findings = HardcodedApiKeyRule().check(f)
    assert findings == []


def test_applies_to_py_file(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("")
    assert AwsAccessKeyRule().applies_to(f) is True


def test_applies_to_yml_file(tmp_path):
    f = tmp_path / "config.yml"
    f.write_text("")
    assert AwsAccessKeyRule().applies_to(f) is True


def test_does_not_apply_to_image(tmp_path):
    f = tmp_path / "photo.png"
    f.write_text("")
    assert AwsAccessKeyRule().applies_to(f) is False


def test_credential_url_detected_in_code(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('DB_URL = "postgresql://admin:s3cr3t@prod-db:5432/mydb"\n')
    findings = CredentialUrlRule().check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_credential_url_not_flagged_in_trufflehog_config(tmp_path):
    """Regression: VGL-S007 must skip .trufflehog.toml — suppression files
    intentionally contain credential-like patterns as detection regexes."""
    f = tmp_path / ".trufflehog.toml"
    f.write_text("regex = '''postgresql://user:pass@host'''\n")
    assert CredentialUrlRule().check(f) == []
    assert CredentialUrlRule().applies_to(f) is False


def test_credential_url_not_flagged_in_gitleaksignore(tmp_path):
    """gitleaksignore has no recognised text extension — engine skips it entirely."""
    f = tmp_path / ".gitleaksignore"
    f.write_text("postgresql://user:pass@host:5432/db\n")
    assert CredentialUrlRule().applies_to(f) is False


# ── VGL-S011 — Insecure config default ────────────────────────────────────────

def test_insecure_os_getenv_secret_detected(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('SECRET_KEY = os.getenv("SECRET_KEY", "changeme")\n')
    assert len(InsecureConfigDefaultRule().check(f)) == 1


def test_insecure_environ_get_jwt_detected(tmp_path):
    f = tmp_path / "auth.py"
    f.write_text('jwt_secret = os.environ.get("JWT_SECRET", "dev-fallback")\n')
    assert len(InsecureConfigDefaultRule().check(f)) == 1


def test_insecure_custom_getter_detected(tmp_path):
    """Regression: cadre config.py pattern that triggered VGL-S011 addition."""
    f = tmp_path / "config.py"
    f.write_text(
        '        return self._get("CADRE_SECRET_KEY", "/cadre/secret_key", "dev-secret-key-change-in-prod")\n'
    )
    assert len(InsecureConfigDefaultRule().check(f)) == 1


def test_insecure_password_getenv_detected(tmp_path):
    f = tmp_path / "settings.py"
    f.write_text('DB_PWD = os.getenv("DB_PASSWORD", "admin")\n')
    assert len(InsecureConfigDefaultRule().check(f)) == 1


def test_no_default_not_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('KEY = os.getenv("SECRET_KEY")\n')
    assert InsecureConfigDefaultRule().check(f) == []


def test_non_secret_var_not_flagged(tmp_path):
    f = tmp_path / "config.py"
    f.write_text('LEVEL = os.getenv("LOG_LEVEL", "info")\n')
    assert InsecureConfigDefaultRule().check(f) == []


def test_dynamic_default_not_flagged(tmp_path):
    """Fallback to another env var is acceptable — no string literal default."""
    f = tmp_path / "config.py"
    f.write_text('KEY = os.getenv("SECRET_KEY", os.environ.get("FALLBACK_KEY"))\n')
    assert InsecureConfigDefaultRule().check(f) == []
