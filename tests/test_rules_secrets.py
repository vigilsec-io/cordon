import pytest
from pathlib import Path
from vigil.rules.secrets import (
    AwsAccessKeyRule, HardcodedPasswordRule, HardcodedApiKeyRule,
    EvalInjectionRule, ShellTrueRule, OsSystemRule,
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
