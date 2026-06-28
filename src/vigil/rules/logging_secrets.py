"""
VGL-LOG001  HIGH  Sensitive data written to logs (CWE-532)
             AI models frequently suggest logging request objects, response bodies,
             and variable dumps that contain passwords, tokens, and PII.
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
