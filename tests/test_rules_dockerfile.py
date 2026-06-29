from pathlib import Path
import pytest
from vigil.rules.dockerfile import (
    DockerfileEnvSecretRule, DockerfileCurlBashRule,
    DockerfileInsecureFetchRule, DockerfileAddLocalRule,
    DockerfileWildcardCopyRule, DockerfileChmod777Rule,
)
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


# ── VGL-DF004 — curl|bash pipe ───────────────────────────────────────────────

class TestDockerfileCurlBashRule:
    rule = DockerfileCurlBashRule()

    def test_detects_curl_pipe_bash(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/install.sh | bash\n")
        assert self.rule.check(f)

    def test_detects_wget_pipe_sh(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN wget -qO- https://example.com/setup.sh | sh\n")
        assert self.rule.check(f)

    def test_detects_curl_pipe_python(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nRUN curl https://bootstrap.pypa.io/get-pip.py | python3\n")
        assert self.rule.check(f)

    def test_ignores_curl_without_pipe(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/file.tar.gz -o file.tar.gz\n")
        assert not self.rule.check(f)

    def test_ignores_pipe_to_non_shell(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl https://example.com/data.json | jq .\n")
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl https://example.com/install.sh | bash\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DF004"

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN wget https://get.docker.com | sh\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_fix_mentions_checksum(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl https://example.com/install.sh | bash\n")
        assert "sha256sum" in self.rule.check(f)[0].fix

    def test_does_not_apply_to_compose(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        assert not self.rule.applies_to(f)


# ── VGL-DF005 — insecure fetch ───────────────────────────────────────────────

class TestDockerfileInsecureFetchRule:
    rule = DockerfileInsecureFetchRule()

    def test_detects_curl_insecure(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl --insecure https://example.com/file.sh -o file.sh\n")
        assert self.rule.check(f)

    def test_detects_curl_k_flag(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl -k https://example.com/file.sh -o file.sh\n")
        assert self.rule.check(f)

    def test_detects_wget_no_check_cert(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN wget --no-check-certificate https://example.com/file.sh\n")
        assert self.rule.check(f)

    def test_ignores_safe_curl(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl -fsSL https://example.com/file.sh -o file.sh\n")
        assert not self.rule.check(f)

    def test_ignores_safe_wget(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN wget https://example.com/file.sh\n")
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl --insecure https://example.com/file -o f\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DF005"

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN curl -k https://example.com/file -o f\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH


# ── VGL-DF006 — ADD for local files ──────────────────────────────────────────

class TestDockerfileAddLocalRule:
    rule = DockerfileAddLocalRule()

    def test_detects_add_local_file(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nADD requirements.txt /app/\n")
        assert self.rule.check(f)

    def test_detects_add_dot(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nADD . /app\n")
        assert self.rule.check(f)

    def test_ignores_add_remote_url(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nADD https://example.com/file.tar.gz /tmp/\n")
        assert not self.rule.check(f)

    def test_ignores_copy(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY requirements.txt /app/\n")
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nADD app.tar.gz /app/\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DF006"

    def test_finding_is_medium(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nADD requirements.txt /app/\n")
        assert self.rule.check(f)[0].severity == Severity.MEDIUM

    def test_finding_mentions_copy(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nADD myfile.sh /app/\n")
        assert "COPY" in self.rule.check(f)[0].fix


# ── VGL-DF007 — COPY . without .dockerignore ─────────────────────────────────

class TestDockerfileWildcardCopyRule:
    rule = DockerfileWildcardCopyRule()

    def test_detects_copy_dot_without_dockerignore(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY . /app\n")
        assert self.rule.check(f)

    def test_ignores_copy_dot_when_dockerignore_exists(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY . /app\n")
        (tmp_path / ".dockerignore").write_text(".git\n.env\n")
        assert not self.rule.check(f)

    def test_ignores_copy_from_stage(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY --from=builder . /app\n")
        assert not self.rule.check(f)

    def test_ignores_copy_specific_file(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY requirements.txt /app/\n")
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY . /app\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DF007"

    def test_finding_is_high(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY . /app\n")
        assert self.rule.check(f)[0].severity == Severity.HIGH

    def test_fix_mentions_git_and_env(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM python:3.12\nCOPY . .\n")
        fix = self.rule.check(f)[0].fix
        assert ".git" in fix and ".env" in fix


# ── VGL-DF008 — chmod 777 ────────────────────────────────────────────────────

class TestDockerfileChmod777Rule:
    rule = DockerfileChmod777Rule()

    def test_detects_chmod_777(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod 777 /app\n")
        assert self.rule.check(f)

    def test_detects_chmod_a_plus_rwx(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod a+rwx /app/entrypoint.sh\n")
        assert self.rule.check(f)

    def test_ignores_chmod_755(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod 755 /app/entrypoint.sh\n")
        assert not self.rule.check(f)

    def test_ignores_chmod_644(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod 644 /app/config.json\n")
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod 777 /tmp/script.sh\n")
        assert self.rule.check(f)[0].rule_id == "VGL-DF008"

    def test_finding_is_medium(self, tmp_path):
        f = tmp_path / "Dockerfile"
        f.write_text("FROM ubuntu:22.04\nRUN chmod 777 /tmp\n")
        assert self.rule.check(f)[0].severity == Severity.MEDIUM

    def test_does_not_apply_to_compose(self, tmp_path):
        f = tmp_path / "docker-compose.yml"
        assert not self.rule.applies_to(f)
