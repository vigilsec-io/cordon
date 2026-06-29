import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SAFE_PUBLIC_PORTS = {80, 443}

_SECRET_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PASS|PWD|CREDENTIALS?|CREDS|PRIVATE",
    re.IGNORECASE,
)


def _is_compose(path: Path) -> bool:
    name = path.name
    return (
        "docker-compose" in name or name in ("compose.yml", "compose.yaml")
    ) and path.suffix in (".yml", ".yaml")


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
        return _is_compose(path)

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
        return _is_compose(path)

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
                if (val and _SECRET_NAME.search(name)
                        and not _is_var_ref(val)
                        and not _is_file_secret_ref(name, val)):
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
                if (val and _SECRET_NAME.search(name)
                        and not _is_var_ref(val)
                        and not _is_file_secret_ref(name, val)):
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


class DockerPrivilegedRule(Rule):
    """VGL-D003 — privileged: true grants container full host kernel access."""

    id = "VGL-D003"
    name = "Docker container runs in privileged mode"
    severity = Severity.CRITICAL

    _PAT = re.compile(r"^\s*privileged\s*:\s*true\b", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return _is_compose(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Container runs in privileged mode — grants full host kernel access and disables all seccomp/AppArmor protections",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix="Remove 'privileged: true'. Use specific capabilities instead: cap_add: [NET_ADMIN] or the minimum capability needed.",
                ))
        return findings


class DockerHostNetworkRule(Rule):
    """VGL-D004 — network_mode: host removes Docker network isolation."""

    id = "VGL-D004"
    name = "Docker container uses host network mode"
    severity = Severity.HIGH

    _PAT = re.compile(r"^\s*network_mode\s*:\s*['\"]?host['\"]?\s*$", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return _is_compose(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="network_mode: host removes Docker network isolation — container shares the host network stack",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix="Remove 'network_mode: host'. Use a named bridge network: 'networks: [backend]'. Host networking exposes all host ports inside the container and bypasses inter-container isolation.",
                ))
        return findings


class DockerSocketMountRule(Rule):
    """VGL-D005 — Docker socket mounted into container = full container escape."""

    id = "VGL-D005"
    name = "Docker socket mounted into container — full container escape vector"
    severity = Severity.CRITICAL

    _PAT = re.compile(r"/var/run/docker\.sock")

    def applies_to(self, path: Path) -> bool:
        return _is_compose(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Docker socket mounted into container — any process inside can control the Docker daemon and escape to the host",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix="Remove the docker.sock volume mount. If the container genuinely needs Docker access (e.g. CI runner), use Docker-in-Docker (dind) or a scoped proxy like Tecnativa/docker-socket-proxy with an allowlist of safe commands.",
                ))
        return findings


class DockerDangerousVolumeRule(Rule):
    """VGL-D006 — sensitive host paths mounted into container."""

    id = "VGL-D006"
    name = "Sensitive host path mounted into container"
    severity = Severity.HIGH

    _DANGEROUS = re.compile(r"(/etc|/proc|/sys|/root|/home)\s*(?::|$)")
    _SOCK = re.compile(r"docker\.sock")  # already caught by VGL-D005

    def applies_to(self, path: Path) -> bool:
        return _is_compose(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if self._SOCK.search(stripped):
                continue
            m = self._DANGEROUS.search(stripped)
            if m:
                dangerous_path = m.group(1)
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Sensitive host path '{dangerous_path}' mounted into container — allows reading/modifying host system files",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix=f"Remove the '{dangerous_path}' volume mount. Mounting system paths into containers allows privilege escalation and host filesystem modification. Use named Docker volumes or copy only the specific files needed.",
                ))
        return findings
