import pytest
from vigil.rules.docker import DockerPortExposureRule, DockerComposeEnvSecretRule
from vigil.rules.base import Severity

rule = DockerPortExposureRule()
env_rule = DockerComposeEnvSecretRule()


def test_unsafe_compose_flags_exposed_ports(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert len(findings) >= 2
    assert all(f.severity == Severity.CRITICAL for f in findings)
    ports_mentioned = " ".join(f.message for f in findings)
    assert "8000" in ports_mentioned
    assert "5432" in ports_mentioned


def test_safe_compose_returns_no_findings(safe_compose):
    findings = rule.check(safe_compose)
    assert findings == []


def test_nginx_ports_80_443_are_exempt(safe_compose):
    findings = rule.check(safe_compose)
    assert not any("80" in f.message or "443" in f.message for f in findings)


def test_finding_includes_127_fix(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert findings
    assert findings[0].fix is not None
    assert "127.0.0.1" in findings[0].fix


def test_finding_includes_line_number(unsafe_compose):
    findings = rule.check(unsafe_compose)
    assert all(f.line is not None and f.line > 0 for f in findings)


def test_applies_to_compose_yml(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_applies_to_compose_override(tmp_path):
    f = tmp_path / "docker-compose.override.yml"
    f.write_text("")
    assert rule.applies_to(f) is True


def test_does_not_apply_to_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("")
    assert rule.applies_to(f) is False


def test_does_not_apply_to_plain_yaml(tmp_path):
    f = tmp_path / "config.yaml"
    f.write_text("")
    assert rule.applies_to(f) is False


# ── VGL-D002 tests ────────────────────────────────────────────────────────────

_COMPOSE_LIST_SECRET = """\
services:
  api:
    environment:
      - DB_PASSWORD=supersecret
      - PORT=8080
      - API_KEY=abc123
"""

_COMPOSE_MAP_SECRET = """\
services:
  api:
    environment:
      DB_PASSWORD: supersecret
      PORT: "8080"
      SECRET_KEY: mysecretvalue
"""

_COMPOSE_VAR_REFS = """\
services:
  api:
    environment:
      - DB_PASSWORD=${DB_PASSWORD}
      - API_KEY=$API_KEY
      DB_TOKEN: ${TOKEN}
"""

_COMPOSE_CLEAN = """\
services:
  api:
    image: python:3.12-slim
    ports:
      - "127.0.0.1:8000:8000"
    environment:
      - PORT=8080
      - APP_ENV=production
"""


def test_list_style_secret_flagged(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_LIST_SECRET)
    findings = env_rule.check(f)
    assert len(findings) == 2
    names = " ".join(fi.message for fi in findings)
    assert "DB_PASSWORD" in names
    assert "API_KEY" in names


def test_mapping_style_secret_flagged(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_MAP_SECRET)
    findings = env_rule.check(f)
    assert len(findings) == 2
    names = " ".join(fi.message for fi in findings)
    assert "DB_PASSWORD" in names
    assert "SECRET_KEY" in names


def test_variable_references_not_flagged(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_VAR_REFS)
    findings = env_rule.check(f)
    assert findings == []


def test_non_secret_names_not_flagged(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_CLEAN)
    findings = env_rule.check(f)
    assert findings == []


def test_finding_has_line_number(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_LIST_SECRET)
    findings = env_rule.check(f)
    assert all(fi.line is not None and fi.line > 0 for fi in findings)


def test_finding_severity_is_high(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_LIST_SECRET)
    findings = env_rule.check(f)
    assert all(fi.severity == Severity.HIGH for fi in findings)


def test_d002_applies_to_compose_yml(tmp_path):
    f = tmp_path / "docker-compose.yml"
    f.write_text("")
    assert env_rule.applies_to(f) is True


def test_d002_does_not_apply_to_python(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("")
    assert env_rule.applies_to(f) is False


# ── _FILE suffix regression (Docker secrets pattern) ─────────────────────────

_COMPOSE_DOCKER_SECRETS = """\
services:
  db:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: forge
      POSTGRES_USER: forge
      POSTGRES_PASSWORD_FILE: /run/secrets/db_password
    secrets:
      - db_password
secrets:
  db_password:
    file: /home/ubuntu/forge/.db_password
"""

_COMPOSE_DOCKER_SECRETS_LIST = """\
services:
  db:
    environment:
      - POSTGRES_PASSWORD_FILE=/run/secrets/db_password
"""

_COMPOSE_REAL_HARDCODED_FILE_VAR = """\
services:
  db:
    environment:
      POSTGRES_PASSWORD_FILE: /some/other/path/plaintext_password
"""


def test_docker_file_secret_pattern_not_flagged_map(tmp_path):
    """POSTGRES_PASSWORD_FILE: /run/secrets/... is Docker's secure pattern — must not be flagged."""
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_DOCKER_SECRETS)
    findings = env_rule.check(f)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_docker_file_secret_pattern_not_flagged_list(tmp_path):
    """List-style _FILE=/run/secrets/... is also safe — Docker secrets."""
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_DOCKER_SECRETS_LIST)
    findings = env_rule.check(f)
    assert findings == [], f"Expected no findings, got: {findings}"


def test_file_suffix_non_secrets_path_still_flagged(tmp_path):
    """_FILE suffix with a non-/run/secrets/ path is not a Docker secret — still flag it."""
    f = tmp_path / "docker-compose.yml"
    f.write_text(_COMPOSE_REAL_HARDCODED_FILE_VAR)
    findings = env_rule.check(f)
    assert len(findings) == 1
    assert "POSTGRES_PASSWORD_FILE" in findings[0].message
