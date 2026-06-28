"""
VGL-AUTH001  CRITICAL  JWT algorithm=none — signature verification bypassed
VGL-AUTH002  CRITICAL  JWT verify_signature disabled — any token accepted
VGL-AUTH003  HIGH      Weak or hardcoded web framework secret key
VGL-AUTH004  HIGH      Flask/Django debug mode enabled in code
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_CODE_EXTS = {".py", ".js", ".ts", ".rb", ".go", ".java"}


def _scan_auth(path: Path, patterns: list[tuple], exts: set[str]) -> list[Finding]:
    if path.suffix not in exts:
        return []
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
        for pat, rule_id, severity, message, fix in patterns:
            if pat.search(line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=fix,
                ))
                break
    return findings


# ── VGL-AUTH001 — JWT algorithm=none ──────────────────────────────────────────

class JwtAlgorithmNoneRule(Rule):
    id = "VGL-AUTH001"
    name = "JWT algorithm=none — signature verification bypassed"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r"""(?:algorithms?\s*=\s*\[?\s*["']none["']|algorithm\s*=\s*["']none["'])""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        return _scan_auth(path, [(
            self._PAT, self.id, self.severity,
            "JWT algorithm='none' — tokens are accepted without signature verification",
            "Explicitly set algorithm='HS256' (or RS256/ES256 for asymmetric). "
            "Never include 'none' in the algorithms list. "
            "CVE-2015-9235: attackers craft unsigned tokens to impersonate any user.",
        )], _CODE_EXTS)


# ── VGL-AUTH002 — JWT verify_signature disabled ───────────────────────────────

class JwtVerifyDisabledRule(Rule):
    id = "VGL-AUTH002"
    name = "JWT verify_signature disabled — any token accepted"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r"""options\s*=\s*\{[^}]*["\']verify_signature["']\s*:\s*False""",
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
                    message="JWT signature verification disabled — token claims are trusted without cryptographic proof",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Remove verify_signature: False from jwt.decode() options. "
                        "This option is intended for debugging only — in production it accepts "
                        "any token, signed or not, making authentication meaningless."
                    ),
                ))
        return findings


# ── VGL-AUTH003 — Weak framework secret key ───────────────────────────────────

class WeakSecretKeyRule(Rule):
    id = "VGL-AUTH003"
    name = "Weak or hardcoded web framework secret key"
    severity = Severity.HIGH

    # Matches: SECRET_KEY = "secret", app.secret_key = "changeme", etc.
    _WEAK_VALUES = re.compile(
        r"""(?:secret_key|SECRET_KEY|app\.secret(?:_key)?)\s*=\s*"""
        r"""["'](?:secret|changeme|dev|debug|test|testing|password|1234|"""
        r"""development|insecure|unsafe|replace.?me|your.?secret|django.insecure)[^"']*["']""",
        re.IGNORECASE,
    )
    # Also catch very short secrets (< 16 chars in quotes after the assignment)
    _SHORT_SECRET = re.compile(
        r"""(?:secret_key|SECRET_KEY)\s*=\s*["'][^"']{1,15}["']""",
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
            if self._WEAK_VALUES.search(line) or self._SHORT_SECRET.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Weak or hardcoded secret key — sessions and tokens can be forged",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Generate a strong random key: python -c \"import secrets; print(secrets.token_hex(32))\". "
                        "Store it in a secrets manager (AWS SSM, Azure Key Vault, Vault) and inject at runtime. "
                        "A guessable SECRET_KEY lets attackers forge signed cookies and session tokens."
                    ),
                ))
        return findings


# ── VGL-AUTH004 — Debug mode enabled in code ─────────────────────────────────

class DebugModeEnabledRule(Rule):
    id = "VGL-AUTH004"
    name = "Debug mode enabled in framework code"
    severity = Severity.HIGH

    _FLASK_DEBUG = re.compile(r"""app\.run\s*\([^)]*debug\s*=\s*True""", re.IGNORECASE)
    _DJANGO_DEBUG = re.compile(r"""^DEBUG\s*=\s*True""", re.IGNORECASE)

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
            if self._FLASK_DEBUG.search(line) or self._DJANGO_DEBUG.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Debug mode enabled — stack traces, env vars, and internal routes exposed to users",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Set DEBUG = False in production. "
                        "Control via environment variable: DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'. "
                        "Flask debug mode also enables the interactive debugger — remote code execution if exposed."
                    ),
                ))
        return findings
