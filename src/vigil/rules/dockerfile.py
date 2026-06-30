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
                    fix="Never bake DB URLs with credentials into images. Inject at runtime via environment variables from a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler).",
                    category="secret_in_layer",
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
                fix="Inject at runtime via environment variables or Docker secrets — never bake into image layers. Use a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler).",
                category="secret_in_layer",
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
            category="root_user",
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
                    category="unpinned_image",
                ))
        return findings


class DockerfileCurlBashRule(Rule):
    """VGL-DF004 — curl|bash or wget|sh in RUN — supply chain attack vector."""

    id = "VGL-DF004"
    name = "curl|bash or wget|sh pipe in Dockerfile RUN instruction"
    severity = Severity.HIGH

    _RUN = re.compile(r"^RUN\b", re.IGNORECASE)
    _PIPE = re.compile(
        r"(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|ash|dash|fish|python3?|ruby|node|perl)\b",
        re.IGNORECASE,
    )

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
            if self._RUN.match(stripped) and self._PIPE.search(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="curl|bash pipe in RUN — executes arbitrary remote code during image build (supply chain attack vector)",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Download the script first, verify its checksum, then execute: RUN curl -fsSL https://example.com/install.sh -o install.sh && echo 'EXPECTED_SHA256  install.sh' | sha256sum -c - && bash install.sh",
                ))
        return findings


class DockerfileInsecureFetchRule(Rule):
    """VGL-DF005 — curl/wget with TLS verification disabled in RUN."""

    id = "VGL-DF005"
    name = "TLS verification disabled in Dockerfile RUN fetch"
    severity = Severity.HIGH

    _RUN = re.compile(r"^RUN\b", re.IGNORECASE)
    _INSECURE = re.compile(
        r"curl\b[^\n]*(?:--insecure|-k\b)|wget\b[^\n]*--no-check-certificate",
        re.IGNORECASE,
    )

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
            if self._RUN.match(stripped) and self._INSECURE.search(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="TLS certificate verification disabled in RUN fetch — allows MITM attacks during image build",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Remove --insecure / -k / --no-check-certificate. Fix the underlying TLS issue instead (install CA bundle: apt-get install -y ca-certificates, or use the correct URL). Disabling TLS allows man-in-the-middle attacks at build time.",
                ))
        return findings


class DockerfileAddLocalRule(Rule):
    """VGL-DF006 — ADD used for local files instead of COPY."""

    id = "VGL-DF006"
    name = "ADD used for local files — use COPY instead"
    severity = Severity.MEDIUM

    # ADD <local-src> <dest> — exclude http/https URLs (legitimate ADD use case)
    _PAT = re.compile(r"^ADD\s+(?!https?://)(?!--chown)(\S+)\s+", re.IGNORECASE)

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
            if stripped.startswith("#"):
                continue
            m = self._PAT.match(stripped)
            if m:
                src = m.group(1)
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"ADD used for local file '{src}' — prefer COPY which has simpler, more predictable behavior",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Replace ADD with COPY. ADD silently decompresses .tar.gz archives and can introduce unintended files. Reserve ADD only for remote URLs; even then RUN curl + verification is preferred.",
                ))
        return findings


class DockerfileWildcardCopyRule(Rule):
    """VGL-DF007 — COPY . <dest> without .dockerignore risks context leakage."""

    id = "VGL-DF007"
    name = "COPY . without .dockerignore — risks leaking .git, .env, credentials"
    severity = Severity.HIGH

    # COPY . <dest> but NOT COPY --from=<stage> . <dest> (multi-stage, not context copy)
    _PAT = re.compile(r"^COPY\s+(?!--from\b)\.\s+\S+", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return "Dockerfile" in path.name

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []
        if (path.parent / ".dockerignore").exists():
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if self._PAT.match(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="COPY . copies the entire build context — no .dockerignore found; .git, .env, and credential files will be baked into the image",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Create .dockerignore in the same directory as the Dockerfile with at minimum:\n.git\n.env\n*.env\n*.key\n*.pem\n.aws\n.ssh\n__pycache__\nnode_modules",
                ))
        return findings


class DockerfileChmod777Rule(Rule):
    """VGL-DF008 — chmod 777 or world-writable permissions in RUN."""

    id = "VGL-DF008"
    name = "World-writable permissions set in Dockerfile (chmod 777)"
    severity = Severity.MEDIUM

    _RUN = re.compile(r"^RUN\b", re.IGNORECASE)
    _PAT = re.compile(r"chmod\s+(?:777|[ao][=+]rwx)", re.IGNORECASE)

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
            if self._RUN.match(stripped) and self._PAT.search(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="World-writable permissions (chmod 777) — any process in the container can modify these files",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix="Use minimum required permissions: chmod 755 for executables, chmod 644 for config files. Pair with ownership: RUN chown -R appuser:appuser /app && chmod 755 /app/entrypoint.sh",
                ))
        return findings
