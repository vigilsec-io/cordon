import re
from pathlib import Path
from .base import Finding, Rule, Severity


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
