"""
VGL-LOG001  HIGH      Sensitive data written to logs (CWE-532)
VGL-LOG002  HIGH      Error details leaked in HTTP response body (stack trace / exception message)
VGL-LOG003  MEDIUM    Silent exception swallowing in authentication/security context
VGL-LOG004  MEDIUM    CRLF injection risk — user-controlled query params logged directly
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_CODE_EXTS = {".py", ".js", ".ts", ".go", ".java", ".rb"}

# Security-sensitive variable names
_SENSITIVE = re.compile(
    r"""\b(?:password|passwd|pwd|secret|api_key|apikey|auth_key|access_key|"""
    r"""private_key|token|jwt|bearer|credential|ssn|credit_card|card_number|"""
    r"""cvv|pin|otp|mfa_code|session_key|encryption_key)\b""",
    re.IGNORECASE,
)

# Python logging calls
_PY_LOG = re.compile(
    r"""(?:logger|logging|log)\s*\.\s*(?:debug|info|warning|warn|error|exception|critical)\s*\(""",
    re.IGNORECASE,
)
# Python print
_PY_PRINT = re.compile(r"""\bprint\s*\(""")

# JS/TS console
_JS_LOG = re.compile(
    r"""console\s*\.\s*(?:log|debug|info|warn|error|dir|trace)\s*\(""",
    re.IGNORECASE,
)

# Go log
_GO_LOG = re.compile(
    r"""(?:log|logger)\s*\.\s*(?:Print|Printf|Println|Fatal|Fatalf|Panicf?)\s*\(""",
)

# Java log4j / slf4j
_JAVA_LOG = re.compile(
    r"""(?:logger|log|LOG)\s*\.\s*(?:debug|info|warn|error|trace|fatal)\s*\(""",
    re.IGNORECASE,
)

# Ruby Rails logger
_RUBY_LOG = re.compile(
    r"""(?:logger|Rails\.logger|puts|p)\s*\.\s*(?:debug|info|warn|error|fatal)?\s*[\.(]""",
    re.IGNORECASE,
)

# Logging entire request/response objects (always risky — may contain auth headers, bodies)
_REQUEST_OBJ = re.compile(
    r"""(?:request(?:\.body|\.headers|\.form|\.json|\.data)?|response\.(?:text|body|content)|"""
    r"""environ\b|headers\b)\s*[,)]""",
    re.IGNORECASE,
)


class LoggingSecretsRule(Rule):
    id = "VGL-LOG001"
    name = "Sensitive data written to logs (CWE-532)"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []

        ext = path.suffix
        findings = []

        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//", "*")):
                continue
            if "vigil: ignore" in line:
                continue

            # Determine if this line has a logging call
            is_log_line = False
            if ext == ".py":
                is_log_line = bool(_PY_LOG.search(line) or _PY_PRINT.search(line))
            elif ext in (".js", ".ts"):
                is_log_line = bool(_JS_LOG.search(line))
            elif ext == ".go":
                is_log_line = bool(_GO_LOG.search(line))
            elif ext == ".java":
                is_log_line = bool(_JAVA_LOG.search(line))
            elif ext == ".rb":
                is_log_line = bool(_RUBY_LOG.search(line))

            if not is_log_line:
                continue

            # Check if the logged value looks security-sensitive
            if _SENSITIVE.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Security-sensitive value written to logs — credentials may appear in log files and monitoring",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Remove the sensitive variable from the log call, or mask it: "
                        "log the first 4 chars only (token[:4] + '***') or log its type/length. "
                        "Log files are often aggregated, indexed, and retained for months — "
                        "any secret that appears in logs should be considered compromised."
                    ),
                ))
            elif _REQUEST_OBJ.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Full request/response object logged — may contain Authorization headers, cookies, or PII",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Log only the fields you need: method, path, status code. "
                        "Never log request.headers (contains Authorization), request.body (may contain passwords), "
                        "or full response bodies. Redact before logging: {k: v for k, v in headers.items() "
                        "if k.lower() not in ('authorization', 'cookie', 'x-api-key')}."
                    ),
                ))

        return findings


# ── VGL-LOG002 — Error details leaked in HTTP response ────────────────────────

class ErrorLeakRule(Rule):
    """VGL-LOG002 — Returning raw exception messages or tracebacks in HTTP responses
    exposes internal stack frames, library versions, file paths, and SQL queries to attackers."""

    id = "VGL-LOG002"
    name = "Error details leaked in HTTP response body (CWE-209)"
    severity = Severity.HIGH

    # return str(e) / return str(exception) / return str(ex)
    # Excludes tuple returns whose first element is a bool/None — those are internal
    # utility patterns (e.g. `return False, str(e)[:80]`), not HTTP responses.
    _STR_EXC = re.compile(
        r"""\breturn\b(?!\s+(?:True|False|None)\s*,).*\bstr\s*\(\s*(?:e|ex|exc|err|error|exception|exp)\s*\)""",
        re.IGNORECASE,
    )
    # return {"error": str(e)} / return {"detail": str(exc)} / return {"message": str(err)}
    _DICT_STR_EXC = re.compile(
        r"""["'](?:error|detail|message|reason|msg|description)["']\s*:\s*str\s*\(\s*(?:e|ex|exc|err|error|exception)\s*\)""",
        re.IGNORECASE,
    )
    # traceback.format_exc() / traceback.print_exc() returned or printed to response
    _TRACEBACK = re.compile(
        r"""traceback\s*\.\s*(?:format_exc|print_exc|format_exception)\s*\(""",
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
            if self._STR_EXC.search(line) or self._DICT_STR_EXC.search(line) or self._TRACEBACK.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Exception details returned in HTTP response — exposes stack frames, file paths, and library versions to attackers",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Return a generic error message to the client and log the details server-side: "
                        "logger.exception('Unexpected error'); return {'error': 'Internal server error'}. "
                        "Exception messages reveal implementation details that help attackers enumerate vulnerabilities."
                    ),
                ))
        return findings


# ── VGL-LOG003 — Silent exception in security context ────────────────────────

class SilentAuthExceptionRule(Rule):
    """VGL-LOG003 — Swallowing exceptions silently in auth/security code masks failures.
    A failed authentication that throws but is silently caught may appear as a success."""

    id = "VGL-LOG003"
    name = "Silent exception swallowing in authentication/security context"
    severity = Severity.MEDIUM

    # Match files that have security-relevant content
    _SECURITY_CONTEXT = re.compile(
        r"""\b(?:login|logout|authenticate|verify|authoriz|permission|password|token|"""
        r"""credential|session|jwt|oauth|bearer|mfa|totp|2fa)\b""",
        re.IGNORECASE,
    )
    # except: pass  or  except Exception: pass  (possibly with comment)
    _EXCEPT_PAT = re.compile(r"^\s*except\s*(?:\w+\s*(?:as\s+\w+)?\s*)?:\s*(?:#.*)?$")
    _PASS_PAT = re.compile(r"^\s*pass\s*(?:#.*)?$")

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []

        # Only scan files with security-relevant context
        if not self._SECURITY_CONTEXT.search(content):
            return []

        lines = content.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if "vigil: ignore" in line:
                continue
            if self._EXCEPT_PAT.match(line):
                # Check if the very next non-empty line is `pass`
                for j in range(i + 1, min(i + 3, len(lines))):
                    next_line = lines[j]
                    if next_line.strip() == "":
                        continue
                    if self._PASS_PAT.match(next_line):
                        # Check surrounding 10 lines for security context
                        window = "\n".join(lines[max(0, i - 10):i + 10])
                        if self._SECURITY_CONTEXT.search(window):
                            findings.append(Finding(
                                rule_id=self.id,
                                severity=self.severity,
                                message="Silent exception swallowed in security-sensitive context — failures may be invisible",
                                file_path=path,
                                line=i + 1,  # 1-indexed
                                snippet=line.strip()[:120],
                                fix=(
                                    "Always log security exceptions: "
                                    "except AuthenticationError as e: logger.warning('Auth failed: %s', e); raise. "
                                    "Silent failures in auth code can mask brute force attacks, "
                                    "injection attempts, and security control bypasses."
                                ),
                            ))
                    break
        return findings


# ── VGL-LOG004 — CRLF injection via user input in logs ───────────────────────

class CrlfLogInjectionRule(Rule):
    """VGL-LOG004 — Logging user-controlled query parameters or path variables without
    stripping newlines allows log forging: an attacker can inject fake log entries."""

    id = "VGL-LOG004"
    name = "CRLF injection risk — user-controlled input logged without newline sanitization"
    severity = Severity.MEDIUM

    # Log calls
    _LOG_CALL = re.compile(
        r"""(?:logger|logging|log)\s*\.\s*(?:debug|info|warning|warn|error|exception|critical)\s*\(|"""
        r"""console\s*\.\s*(?:log|info|warn|error)\s*\(|"""
        r"""print\s*\(""",
        re.IGNORECASE,
    )
    # User-controlled sources likely to contain newlines
    _USER_INPUT = re.compile(
        r"""request\.(?:args|GET|POST|form|query_params|query_string)\s*[\[\.get]|"""
        r"""request\.(?:headers\.get|path_params\b|cookies\b)|"""
        r"""params\[|query_params\[|request\.path\b""",
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
            if self._LOG_CALL.search(line) and self._USER_INPUT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="CRLF injection risk — user-controlled query/path parameter logged directly; attacker can forge log entries",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Sanitize user input before logging: strip newlines with "
                        "value.replace('\\r', '').replace('\\n', '') or "
                        "re.sub(r'[\\r\\n]', '', value). "
                        "Log injection allows attackers to forge entries that look like legitimate log lines, "
                        "obscuring real security events."
                    ),
                ))
        return findings
