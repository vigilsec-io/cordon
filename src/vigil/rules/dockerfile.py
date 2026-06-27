import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SECRET_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PASS|PWD|CREDENTIALS?|CREDS|PRIVATE",
    re.IGNORECASE,
)


class DockerfileEnvSecretRule(Rule):
    id = "VGL-DF003"
    name = "Dockerfile bakes secret into ENV or ARG layer"
    severity = Severity.HIGH

    _PAT = re.compile(r"^(ENV|ARG)\s+(\w+)=\S+", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return "Dockerfile" in path.name

    _CRED_URL = re.compile(
        r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:@\s]+:[^@\s]+@",
    )

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings: list[Finding] = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            m = self._PAT.match(stripped)
            if not m:
                continue
            instr, name = m.group(1).upper(), m.group(2)
            # Value-based: credential-embedded URL regardless of key name (issue #1)
            value_part = stripped[m.end():]
            if self._CRED_URL.search(value_part):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message=f"Credential-embedded URL baked into {instr} layer: {name}",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Never bake DB URLs with credentials into images. Inject at runtime from SSM.",
                ))
                continue
            # Name-based: secret key name with any value
            if not _SECRET_NAME.search(name):
                continue
            sev = Severity.HIGH if instr == "ENV" else Severity.MEDIUM
            findings.append(Finding(
                rule_id=self.id,
                severity=sev,
                message=f"Secret baked into {instr} layer: {name}",
                file_path=path,
                line=i,
                snippet=stripped[:120],
                fix="Inject at runtime via SSM or Docker secrets — never bake into image layers",
            ))
        return findings


class DockerfileRootUserRule(Rule):
    id = "VGL-DF001"
    name = "Dockerfile runs as root — no USER directive"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return "Dockerfile" in path.name

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text()
        except OSError:
            return []
        if re.search(r"^USER\s+\S", content, re.MULTILINE):
            return []
        return [Finding(
            rule_id=self.id,
            severity=self.severity,
            message="Dockerfile has no USER directive — container runs as root",
            file_path=path,
            fix=(
                "Add before CMD/ENTRYPOINT:\n"
                "  RUN useradd -r -u 1001 appuser\n"
                "  USER appuser"
            ),
        )]


class DockerfileLatestTagRule(Rule):
    id = "VGL-DF002"
    name = "Dockerfile uses unpinned :latest base image"
    severity = Severity.MEDIUM
    _FROM = re.compile(r"^FROM\s+(\S+)", re.MULTILINE)

    def applies_to(self, path: Path) -> bool:
        return "Dockerfile" in path.name

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped.startswith("FROM "):
                continue
            parts = stripped.split()
            if len(parts) < 2:
                continue
            image = parts[1]
            if image == "scratch":
                continue
            is_unpinned = ":latest" in image or (":" not in image and "@" not in image)
            if is_unpinned:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Unpinned base image: {image}",
                    file_path=path,
                    line=i,
                    snippet=stripped,
                    fix='Pin to a specific digest or tag: e.g. "python:3.12.3-slim"',
                ))
        return findings
