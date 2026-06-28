"""
VGL-SSRF001  CRITICAL  HTTP call with user-controlled URL (Server-Side Request Forgery)
VGL-SQL001   CRITICAL  SQL query built with f-string or string concatenation
VGL-SQL002   CRITICAL  ORM .raw()/.execute() called with f-string
VGL-CORS001  HIGH      CORS wildcard allow_origins=["*"]
VGL-SSL001   HIGH      SSL verification disabled (verify=False / CERT_NONE)
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_CODE_EXTS = {
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".rs", ".cs",
}
_ALL_EXTS = _CODE_EXTS | {".yml", ".yaml", ".json", ".toml", ".conf", ".ini"}


def _scan(path: Path, pattern: str, rule_id: str, severity: Severity,
          message: str, fix: str, exts: set[str]) -> list[Finding]:
    if path.suffix not in exts:
        return []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except (OSError, PermissionError):
        return []
    rx = re.compile(pattern, re.IGNORECASE)
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith(("#", "//", "*", "<!--")):
            continue
        if "vigil: ignore" in line:
            continue
        if rx.search(line):
            findings.append(Finding(
                rule_id=rule_id,
                severity=severity,
                message=message,
                file_path=path,
                line=i,
                snippet=line.strip()[:120],
                fix=fix,
            ))
    return findings


# ── VGL-SSRF001 ───────────────────────────────────────────────────────────────

class SsrfRule(Rule):
    id = "VGL-SSRF001"
    name = "SSRF — HTTP call with user-controlled URL"
    severity = Severity.CRITICAL

    # Match HTTP client calls where the URL arg references request/user input
    _PAT = re.compile(
        r"""(?:requests|httpx|aiohttp)\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*"""
        r"""\(\s*(?:request\b|.*\b(?:request\.|url_param|user_url|target_url|callback_url|"""
        r"""redirect_url|webhook_url|proxy_url|external_url|input_url))""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//")):
                continue
            if "vigil: ignore" in line:
                continue
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="SSRF risk — HTTP client called with user-controlled URL",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Validate the URL against an allowlist before making the request. "
                        "Never pass user-supplied URLs directly to requests/httpx. "
                        "Use urllib.parse to extract and validate scheme+host first."
                    ),
                ))
        return findings


# ── VGL-SQL001 ────────────────────────────────────────────────────────────────

class SqlInjectionFstringRule(Rule):
    id = "VGL-SQL001"
    name = "SQL injection — query built with f-string or string concatenation"
    severity = Severity.CRITICAL

    # f-string containing SQL keyword
    _FSTR = re.compile(
        r"""f["']\s*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|EXEC)\b[^"']*\{""",
        re.IGNORECASE,
    )
    # String concatenation with SQL keyword
    _CONCAT = re.compile(
        r"""["']\s*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"']{0,80}["']\s*\+""",
        re.IGNORECASE,
    )
    # % formatting with SQL
    _PERCENT = re.compile(
        r"""["'](?:SELECT|INSERT|UPDATE|DELETE)[^"']*%[sd][^"']*["']\s*%\s*""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if "vigil: ignore" in line:
                continue
            if self._FSTR.search(line) or self._CONCAT.search(line) or self._PERCENT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="SQL injection — query constructed via string interpolation",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use parameterized queries: cursor.execute('SELECT ... WHERE id = %s', (user_id,)) "
                        "or ORM query builders. Never interpolate variables directly into SQL strings."
                    ),
                ))
        return findings


# ── VGL-SQL002 ────────────────────────────────────────────────────────────────

class SqlOrmRawRule(Rule):
    id = "VGL-SQL002"
    name = "SQL injection — ORM raw query with f-string"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r"""\.(?:raw|execute|executemany|exec_driver_sql|rawQuery|nativeQuery)\s*\(\s*f["']""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        return _scan(
            path, self._PAT.pattern, self.id, self.severity,
            "SQL injection — ORM raw/execute called with f-string",
            "Pass parameters separately: Model.objects.raw('SELECT ... WHERE id=%s', [user_id]). "
            "Never interpolate variables inside the query string passed to raw() or execute().",
            _CODE_EXTS,
        )


# ── VGL-CORS001 ───────────────────────────────────────────────────────────────

class CorsWildcardRule(Rule):
    id = "VGL-CORS001"
    name = "CORS wildcard — allow_origins=['*']"
    severity = Severity.HIGH

    # FastAPI / Starlette CORSMiddleware
    _MIDDLEWARE = re.compile(
        r"""allow_origins\s*=\s*\[?\s*["']\*["']""",
        re.IGNORECASE,
    )
    # Django CORS_ALLOWED_ORIGINS / CORS_ORIGIN_ALLOW_ALL
    _DJANGO = re.compile(
        r"""CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOWED_ORIGINS\s*=\s*\[["']\*["']""",
        re.IGNORECASE,
    )
    # HTTP response header
    _HEADER = re.compile(
        r"""Access-Control-Allow-Origin['":\s]+\*""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _ALL_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if "vigil: ignore" in line:
                continue
            if self._MIDDLEWARE.search(line) or self._DJANGO.search(line) or self._HEADER.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="CORS wildcard allows requests from any origin",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Restrict to specific origins: allow_origins=['https://yourdomain.com']. "
                        "Wildcard CORS exposes your API to cross-site request forgery from any website."
                    ),
                ))
        return findings


# ── VGL-SSL001 ────────────────────────────────────────────────────────────────

class SslVerifyDisabledRule(Rule):
    id = "VGL-SSL001"
    name = "SSL verification disabled"
    severity = Severity.HIGH

    _PAT = re.compile(
        r"""(?:verify\s*=\s*False|ssl\._create_unverified_context|"""
        r"""CERT_NONE|verify_ssl\s*=\s*False|check_hostname\s*=\s*False|"""
        r"""ssl_verify\s*=\s*False|InsecureRequestWarning|urllib3\.disable_warnings)""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        return _scan(
            path, self._PAT.pattern, self.id, self.severity,
            "SSL verification disabled — vulnerable to man-in-the-middle attacks",
            "Remove verify=False. Fix the underlying certificate issue instead: "
            "add the CA bundle (verify='/path/to/ca-bundle.crt') or trust the cert properly. "
            "Never ship with SSL verification disabled.",
            _CODE_EXTS,
        )
