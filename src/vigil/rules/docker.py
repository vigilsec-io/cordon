import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SAFE_PUBLIC_PORTS = {80, 443}

_SECRET_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PASS|PWD|CREDENTIALS?|CREDS|PRIVATE",
    re.IGNORECASE,
)


def _is_var_ref(val: str) -> bool:
    """True if the value is a shell/compose variable reference like ${VAR} or $VAR."""
    return val.lstrip("\"'").startswith("$")


def _is_file_secret_ref(name: str, val: str) -> bool:
    """True if this is Docker's _FILE suffix pattern for file-based secrets.

    The Docker convention: FOO_PASSWORD_FILE=/run/secrets/foo tells the container
    to read the secret from a file rather than an env var — this is the *more*
    secure approach and must never be flagged as a hardcoded secret.
    """
    return name.upper().endswith("_FILE") and val.startswith("/run/secrets/")


class DockerPortExposureRule(Rule):
    """VGL-D001 — the unique rule no existing IaC tool catches.

    Docker bypasses UFW by rewriting iptables directly.
    A bare "HOST:CONTAINER" port mapping binds to 0.0.0.0 and is reachable
    from the public internet regardless of any ufw deny rules.

    Confirmed gap (2026-06-26): Checkov, Trivy config, Semgrep, Snyk all
    return 0 findings for this pattern. vigil is the only tool that catches it.
    """

    id = "VGL-D001"
    name = "Docker public port binding — bypasses UFW, exposes service to internet"
    severity = Severity.CRITICAL
    _PATTERN = re.compile(r'"(\d+):(\d+)"')

    def applies_to(self, path: Path) -> bool:
        return "docker-compose" in path.name and path.suffix in (".yml", ".yaml")

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            m = self._PATTERN.search(line)
            if not m:
                continue
            try:
                host_port = int(m.group(1))
            except ValueError:
                continue
            if host_port in _SAFE_PUBLIC_PORTS:
                continue
            container_port = m.group(2)
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    f"Port {host_port} bound to 0.0.0.0 — Docker bypasses UFW; "
                    "service is publicly reachable from the internet"
                ),
                file_path=path,
                line=i,
                snippet=line.strip(),
                fix=f'Change to "127.0.0.1:{host_port}:{container_port}" '
                    "(or 0.0.0.0 only for nginx 80/443 which are intentionally public).",
            ))
        return findings


class DockerComposeEnvSecretRule(Rule):
    """VGL-D002 — hardcoded secrets in docker-compose environment blocks.

    Catches values passed directly as plaintext. Variable references like
    ${VAR} or $VAR are safe (pull from host environment) and are not flagged.
    """

    id = "VGL-D002"
    name = "docker-compose environment block contains hardcoded secret"
    severity = Severity.HIGH

    # List style:    - DB_PASSWORD=mysecret
    _LIST_PAT = re.compile(r"^-\s+(\w+)=(.+)")
    # Mapping style: DB_PASSWORD: mysecret  (indented line)
    _MAP_PAT = re.compile(r"^(\w+)\s*:\s+(.+)")

    def applies_to(self, path: Path) -> bool:
        return "docker-compose" in path.name and path.suffix in (".yml", ".yaml")

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings: list[Finding] = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # List style: - KEY=value
            m = self._LIST_PAT.match(stripped)
            if m:
                name, val = m.group(1), m.group(2).strip()
                if val and _SECRET_NAME.search(name) and not _is_var_ref(val):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Hardcoded secret in compose environment: {name}",
                        file_path=path,
                        line=i,
                        snippet=stripped[:120],
                        fix=f"Use a host env reference: - {name}=${{HOST_VAR}}",
                    ))
                continue

            # Mapping style: KEY: value — only check indented lines to avoid
            # top-level compose keys like "version:" or "services:"
            if not (line.startswith("  ") or line.startswith("\t")):
                continue
            m = self._MAP_PAT.match(stripped)
            if m:
                name, val = m.group(1), m.group(2).strip()
                if val and _SECRET_NAME.search(name) and not _is_var_ref(val):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=f"Hardcoded secret in compose environment: {name}",
                        file_path=path,
                        line=i,
                        snippet=stripped[:120],
                        fix=f"Use a host env reference: {name}: ${{HOST_VAR}}",
                    ))
        return findings
