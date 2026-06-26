from pathlib import Path
import pytest
from vigil.rules.dockerfile import DockerfileEnvSecretRule
from vigil.rules.base import Severity

rule = DockerfileEnvSecretRule()


def test_env_password_flagged_as_high(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nENV PASSWORD=supersecret\n")
    findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert "PASSWORD" in findings[0].message


def test_env_api_key_flagged(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nENV API_KEY=abc123\n")
    findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_arg_secret_with_default_flagged_as_medium(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nARG TOKEN=default_token\n")
    findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


def test_arg_without_default_is_clean(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nARG SECRET\n")
    findings = rule.check(f)
    assert findings == []


def test_env_non_secret_is_clean(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nENV PORT=8080\nENV APP_ENV=production\n")
    findings = rule.check(f)
    assert findings == []


def test_finding_has_line_number(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("FROM python:3.12-slim\nWORKDIR /app\nENV DB_PASSWORD=foo\n")
    findings = rule.check(f)
    assert len(findings) == 1
    assert findings[0].line == 3


def test_applies_to_dockerfile(tmp_path):
    f = tmp_path / "Dockerfile"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_dockerfile_prod(tmp_path):
    f = tmp_path / "Dockerfile.prod"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_does_not_apply_to_compose(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("")
    assert rule.applies_to(f) is False
