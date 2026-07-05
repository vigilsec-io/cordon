"""
VGL-PY001  HIGH  Debug bypass without env guard — auth/security conditionally disabled
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_PY_EXTS = {".py"}

# Env-var reads whose key name explicitly signals an auth/security bypass.
# Truthy checks (no default) let any non-empty env var silently disable auth.
_BYPASS_ENV = re.compile(
    r"""os\.(?:environ(?:\.get)?\s*[\[(]|getenv\s*\()\s*["']"""
    r"""(?:SKIP|BYPASS|DISABLE|NO|FAKE)_?"""
    r"""(?:AUTH(?:ENTICATION|ORIZATION)?|SECURITY|SSL_VERIFY|VERIFY|CHECKS?)""",
    re.IGNORECASE,
)

# Hardcoded boolean assignments that explicitly disable auth/security enforcement.
_BYPASS_FLAG = re.compile(
    r"""(?x)
    (?:
        (?:SKIP|BYPASS|DISABLE|NO|FAKE)_AUTH(?:ENTICATION|ORIZATION)?\s*=\s*True
        |
        (?:skip|bypass|no|fake)_auth(?:entication|orization)?\s*=\s*True
        |
        REQUIRE_AUTH(?:ENTICATION)?\s*=\s*False
        |
        AUTH(?:ENTICATION|ORIZATION)?_(?:REQUIRED|ENABLED)\s*=\s*False
        |
        ENFORCE_(?:AUTH(?:ENTICATION|ORIZATION)?|SECURITY|SSL)\s*=\s*False
    )
    """,
    re.IGNORECASE,
)

_FIX = (
    "Remove the bypass entirely. "
    "If a conditional disable is genuinely needed for testing, use an explicit "
    "safe default: os.environ.get('SKIP_AUTH', 'false').lower() == 'true' "
    "and gate it behind a CI-only secret — never a flag that defaults to bypass. "
    "A truthy env-var check (no default) disables auth whenever the variable is "
    "set to any non-empty value, including by accident or by a supply-chain attack."
)


class DebugBypassRule(Rule):
    id = "VGL-PY001"
    name = "Debug bypass without env guard — auth/security conditionally disabled"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _PY_EXTS

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
            if _BYPASS_ENV.search(line) or _BYPASS_FLAG.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "Auth/security bypass controlled by a debug flag — "
                        "an accidentally or maliciously set env var silently disables protection"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=_FIX,
                    category="debug_bypass",
                ))
        return findings
