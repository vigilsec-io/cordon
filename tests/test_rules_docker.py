import pytest
from vigil.rules.docker import (
    DockerPortExposureRule, DockerComposeEnvSecretRule,
    DockerPrivilegedRule, DockerHostNetworkRule,
    DockerSocketMountRule, DockerDangerousVolumeRule,
    DockerAwsCredentialsMountRule,
)
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


# ── VGL-D003 — privileged mode ────────────────────────────────────────────────

_PRIVILEGED_COMPOSE = """\
services:
  worker:
    image: myapp:latest
    privileged: true
"""

_SAFE_COMPOSE_NO_PRIV = """\
services:
  worker:
    image: myapp:latest
    cap_add:
      - NET_ADMIN
"""


class TestDockerPrivilegedRule:
    rule = DockerPrivilegedRule()

    def test_detects_privileged_true(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PRIVILEGED_COMPOSE)
        assert self.rule.check(f)

    def test_ignores_cap_add_instead(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SAFE_COMPOSE_NO_PRIV)
        assert not self.rule.check(f)

    def test_finding_is_critical(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PRIVILEGED_COMPOSE)
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PRIVILEGED_COMPOSE)
        assert self.rule.check(f)[0].rule_id == "VGL-D003"

    def test_fix_mentions_cap_add(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PRIVILEGED_COMPOSE)
        assert "cap_add" in self.rule.check(f)[0].fix

    def test_does_not_apply_to_plain_yaml(self, tmp_path):
        f = tmp_path / "values.yaml"
        assert not self.rule.applies_to(f)


# ── VGL-D004 — host network mode ─────────────────────────────────────────────

_HOST_NETWORK_COMPOSE = """\
services:
  proxy:
    image: nginx:alpine
    network_mode: host
"""

_BRIDGE_NETWORK_COMPOSE = """\
services:
  proxy:
    image: nginx:alpine
    networks:
      - frontend
"""


class TestDockerHostNetworkRule:
    rule = DockerHostNetworkRule()

    def test_detects_network_mode_host(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_HOST_NETWORK_COMPOSE)
        assert self.rule.check(f)

    def test_ignores_bridge_network(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_BRIDGE_NETWORK_COMPOSE)
        assert not self.rule.check(f)

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_HOST_NETWORK_COMPOSE)
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_HOST_NETWORK_COMPOSE)
        assert self.rule.check(f)[0].rule_id == "VGL-D004"

    def test_network_mode_with_quotes(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text('services:\n  app:\n    network_mode: "host"\n')
        assert self.rule.check(f)


# ── VGL-D005 — Docker socket mount ───────────────────────────────────────────

_SOCK_COMPOSE = """\
services:
  ci:
    image: docker:dind
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
"""

_SAFE_VOLUME_COMPOSE = """\
services:
  app:
    volumes:
      - ./data:/data
      - ./logs:/var/log/app
"""


class TestDockerSocketMountRule:
    rule = DockerSocketMountRule()

    def test_detects_docker_sock(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SOCK_COMPOSE)
        assert self.rule.check(f)

    def test_ignores_safe_volumes(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SAFE_VOLUME_COMPOSE)
        assert not self.rule.check(f)

    def test_finding_is_critical(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SOCK_COMPOSE)
        assert self.rule.check(f)[0].severity == Severity.CRITICAL

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SOCK_COMPOSE)
        assert self.rule.check(f)[0].rule_id == "VGL-D005"

    def test_fix_mentions_proxy(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SOCK_COMPOSE)
        assert "proxy" in self.rule.check(f)[0].fix.lower()


# ── VGL-D006 — dangerous volume mounts ───────────────────────────────────────

_DANGEROUS_VOL_COMPOSE = """\
services:
  app:
    volumes:
      - /etc:/etc:ro
      - ./data:/data
"""

_PROC_VOL_COMPOSE = """\
services:
  monitor:
    volumes:
      - /proc:/proc
"""

_HOME_VOL_COMPOSE = """\
services:
  app:
    volumes:
      - /root:/root
"""


class TestDockerDangerousVolumeRule:
    rule = DockerDangerousVolumeRule()

    def test_detects_etc_mount(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_DANGEROUS_VOL_COMPOSE)
        assert self.rule.check(f)

    def test_detects_proc_mount(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PROC_VOL_COMPOSE)
        assert self.rule.check(f)

    def test_detects_root_mount(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_HOME_VOL_COMPOSE)
        assert self.rule.check(f)

    def test_ignores_safe_volumes(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SAFE_VOLUME_COMPOSE)
        assert not self.rule.check(f)

    def test_docker_sock_not_double_flagged(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_SOCK_COMPOSE)
        assert not self.rule.check(f)  # D005 handles this, D006 skips it

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_PROC_VOL_COMPOSE)
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_DANGEROUS_VOL_COMPOSE)
        assert self.rule.check(f)[0].rule_id == "VGL-D006"


# ── VGL-D007 — AWS credentials directory mount ───────────────────────────────

_AWS_MOUNT_TILDE = """\
services:
  api:
    volumes:
      - ~/.aws:/home/appuser/.aws:ro
"""

_AWS_MOUNT_ABSOLUTE = """\
services:
  api:
    volumes:
      - /home/ubuntu/.aws:/home/shield/.aws:ro
"""

_AWS_SCOPED_MOUNT = """\
services:
  api:
    volumes:
      - ~/.aws/scoped/myproject.credentials:/home/appuser/.aws/credentials:ro
      - ~/.aws/scoped/myproject.config:/home/appuser/.aws/config:ro
"""

_AWS_IGNORE_COMMENT = """\
services:
  api:
    volumes:
      - ~/.aws:/home/appuser/.aws:ro  # vigil: ignore — legacy, migration in progress
"""

_NO_AWS_MOUNT = """\
services:
  api:
    volumes:
      - ./data:/data
      - ./logs:/var/log/app
"""


class TestDockerAwsCredentialsMountRule:
    rule = DockerAwsCredentialsMountRule()

    def test_detects_tilde_aws_mount(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_MOUNT_TILDE)
        assert self.rule.check(f)

    def test_detects_absolute_aws_mount(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_MOUNT_ABSOLUTE)
        assert self.rule.check(f)

    def test_scoped_file_mount_not_flagged(self, tmp_path):
        """Scoped single-profile files are the recommended fix — must not be flagged."""
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_SCOPED_MOUNT)
        assert not self.rule.check(f)

    def test_vigil_ignore_suppresses_finding(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_IGNORE_COMMENT)
        assert not self.rule.check(f)

    def test_safe_volumes_not_flagged(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_NO_AWS_MOUNT)
        assert not self.rule.check(f)

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_MOUNT_TILDE)
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_MOUNT_TILDE)
        assert self.rule.check(f)[0].rule_id == "VGL-D007"

    def test_fix_mentions_scoped(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text(_AWS_MOUNT_TILDE)
        assert "scoped" in self.rule.check(f)[0].fix

    def test_applies_to_compose_yml(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        f.write_text("")
        assert self.rule.applies_to(f) is True

    def test_does_not_apply_to_plain_yaml(self, tmp_path):
        f = tmp_path / "values.yaml"
        assert not self.rule.applies_to(f)
