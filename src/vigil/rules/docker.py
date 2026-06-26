import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SAFE_PUBLIC_PORTS = {80, 443}


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
