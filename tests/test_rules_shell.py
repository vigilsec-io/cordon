"""Tests for VGL-S011 — shell script secret injection (ps aux leak)."""
from pathlib import Path
import pytest
from vigil.rules.shell import ShellSecretInjectionRule

rule = ShellSecretInjectionRule()


def _f(tmp_path, content, name="deploy.sh"):
    f = tmp_path / name
    f.write_text(content)
    return f


# applies_to
def test_applies_to_sh(tmp_path):
    assert rule.applies_to(tmp_path / "deploy.sh")

def test_applies_to_bash(tmp_path):
    assert rule.applies_to(tmp_path / "setup.bash")

def test_applies_to_makefile(tmp_path):
    assert rule.applies_to(tmp_path / "Makefile")

def test_does_not_apply_to_py(tmp_path):
    assert rule.applies_to(tmp_path / "script.py") is False

def test_does_not_apply_to_yml(tmp_path):
    assert rule.applies_to(tmp_path / "docker-compose.yml") is False


# VGL-S011: SSH inline secret — the forge/deploy.sh pattern
def test_ssh_inline_secret_flagged(tmp_path):
    code = 'ssh host "DB_PASSWORD=\'$DB_PASSWORD\' alembic upgrade head"'  # vigil: ignore
    f = _f(tmp_path, code)
    findings = rule.check(f)
    assert any(fi.rule_id == "VGL-S011" for fi in findings)

def test_ssh_inline_db_url_flagged(tmp_path):
    code = "ssh user@host \"DB_URL='$FORGE_DB_URL' python3 migrate.py\""  # vigil: ignore
    f = _f(tmp_path, code)
    assert rule.check(f) != []

def test_ssh_inline_token_flagged(tmp_path):
    code = 'ssh host "API_KEY=\\"$MY_API_KEY\\" ./run.sh"'  # vigil: ignore
    f = _f(tmp_path, code)
    assert rule.check(f) != []


# VGL-S011: inline env var before subprocess
def test_inline_env_password_flagged(tmp_path):
    code = "DB_PASSWORD=\"$DB_PASSWORD\" python3 migrate.py"  # vigil: ignore
    f = _f(tmp_path, code)
    assert any(fi.rule_id == "VGL-S011" for fi in rule.check(f))

def test_inline_env_token_flagged(tmp_path):
    code = "API_TOKEN='$MY_TOKEN' ./deploy.sh"  # vigil: ignore
    f = _f(tmp_path, code)
    assert rule.check(f) != []

def test_inline_env_secret_flagged(tmp_path):
    code = "APP_SECRET=$SECRET_VALUE ./server"  # vigil: ignore
    f = _f(tmp_path, code)
    assert rule.check(f) != []


# Safe patterns — must not flag
def test_ssm_fetch_not_flagged(tmp_path):
    code = "DB_URL=$(aws ssm get-parameter --name /forge/db_url --with-decryption --query Parameter.Value --output text)"
    f = _f(tmp_path, code)
    assert rule.check(f) == []

def test_export_not_flagged(tmp_path):
    code = "export DB_PASSWORD"
    f = _f(tmp_path, code)
    assert rule.check(f) == []

def test_non_secret_inline_not_flagged(tmp_path):
    code = "LOG_LEVEL=$LOG_LEVEL ./server"
    f = _f(tmp_path, code)
    assert rule.check(f) == []

def test_comment_line_not_flagged(tmp_path):
    code = "# DB_PASSWORD='$DB_PASSWORD' ./run.sh  -- old approach, do not use"  # vigil: ignore
    f = _f(tmp_path, code)
    assert rule.check(f) == []

def test_ssh_no_secret_not_flagged(tmp_path):
    code = 'ssh host "venv/bin/alembic upgrade head"'
    f = _f(tmp_path, code)
    assert rule.check(f) == []
