"""
VGL-RAND001  HIGH  Weak randomness used for security-sensitive values (CWE-330)
             AI models trained on pre-secrets-module code consistently suggest
             random.random()/randint() for passwords, tokens, and OTP codes.
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_CODE_EXTS = {
    ".py", ".js", ".ts", ".rb", ".go", ".java", ".php", ".rs", ".cs",
}

_SECURITY_NAMES = re.compile(
    r"\b(?:password|passwd|pwd|token|secret|otp|nonce|salt|csrf|"
    r"session_id|api_key|apikey|auth_key|access_key|private_key|"
    r"verification_code|confirm_code|reset_code|invite_code)\b",
    re.IGNORECASE,
)

_WEAK_RAND = re.compile(
    r"\brandom\.(?:random|randint|randrange|choice|uniform|randbytes|sample)\s*\(",
    re.IGNORECASE,
)

# Also catch Math.random() in JS/TS
_JS_RAND = re.compile(r"\bMath\.random\s*\(", re.IGNORECASE)


class WeakRandomnessRule(Rule):
    id = "VGL-RAND001"
    name = "Weak randomness for security-sensitive value (CWE-330)"
    severity = Severity.HIGH

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

            has_weak = _WEAK_RAND.search(line) or _JS_RAND.search(line)
            has_security_name = _SECURITY_NAMES.search(line)

            if has_weak and has_security_name:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Weak randomness used for security-sensitive value — not cryptographically secure",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use secrets.token_hex(32) or secrets.token_urlsafe(32) for tokens/passwords. "
                        "Use secrets.randbelow(n) instead of random.randint(). "
                        "The random module is not cryptographically secure — "
                        "its output can be predicted from prior values."
                    ),
                ))

        return findings
