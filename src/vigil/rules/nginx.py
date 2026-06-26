import re
from pathlib import Path
from .base import Finding, Rule, Severity


def _is_nginx(path: Path) -> bool:
    name = path.name
    parts = path.parts
    return (
        name == "nginx.conf"
        or name.endswith(".nginx")
        or "sites-available" in parts
        or "sites-enabled" in parts
        or "conf.d" in parts
        or ("nginx" in parts and name.endswith(".conf"))
    )


class NginxSecurityHeadersRule(Rule):
    id = "VGL-N001"
    name = "nginx config missing security headers or weak TLS"
    severity = Severity.HIGH

    _CHECKS: list[tuple[re.Pattern, Severity, str, str]] = [
        (
            re.compile(r"server_tokens\s+off", re.IGNORECASE),
            Severity.MEDIUM,
            "server_tokens is not set to off — nginx version exposed in error pages",
            "Add: server_tokens off;",
        ),
        (
            re.compile(r"X-Frame-Options", re.IGNORECASE),
            Severity.HIGH,
            'X-Frame-Options header missing — clickjacking risk',
            'Add: add_header X-Frame-Options "DENY" always;',
        ),
        (
            re.compile(r"X-Content-Type-Options", re.IGNORECASE),
            Severity.MEDIUM,
            "X-Content-Type-Options header missing — MIME-sniffing risk",
            'Add: add_header X-Content-Type-Options "nosniff" always;',
        ),
        (
            re.compile(r"Referrer-Policy", re.IGNORECASE),
            Severity.LOW,
            "Referrer-Policy header missing",
            'Add: add_header Referrer-Policy "no-referrer" always;',
        ),
    ]

    # Matches ssl_protocols lines that include TLSv1.0 or TLSv1.1
    _OLD_TLS = re.compile(
        r"ssl_protocols\b[^;]*(TLSv1(?!\.[23])|TLSv1\.1)",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return _is_nginx(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text()
        except OSError:
            return []
        findings: list[Finding] = []
        for pattern, sev, message, fix in self._CHECKS:
            if not pattern.search(content):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=sev,
                    message=message,
                    file_path=path,
                    fix=fix,
                ))
        m = self._OLD_TLS.search(content)
        if m:
            findings.append(Finding(
                rule_id=self.id,
                severity=Severity.HIGH,
                message=f"Deprecated TLS version in ssl_protocols: {m.group(0).strip()}",
                file_path=path,
                snippet=m.group(0).strip()[:120],
                fix="Use: ssl_protocols TLSv1.2 TLSv1.3;",
            ))
        return findings
