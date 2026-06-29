"""
VGL-JS001  HIGH      process.env secret with hardcoded string fallback — credential baked into bundle
VGL-JS004  HIGH      eval() or new Function() with non-literal argument in JS/TS (CWE-95)
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_JS_EXTS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}

# Security-sensitive env var name patterns
_SENSITIVE_ENV = re.compile(
    r"""(?:SECRET|KEY|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|AUTH|API_KEY|
    APIKEY|ACCESS_KEY|PRIVATE_KEY|JWT|SIGNING|ENCRYPTION|SALT|HMAC)""",
    re.IGNORECASE | re.VERBOSE,
)


# ── VGL-JS001 — process.env secret with string fallback ───────────────────────

class ProcessEnvFallbackRule(Rule):
    id = "VGL-JS001"
    name = "process.env secret with hardcoded string fallback"
    severity = Severity.HIGH

    # process.env.SOME_NAME || "value"  or  process.env.SOME_NAME ?? "value"
    _PAT = re.compile(
        r"""process\.env\.([A-Z_][A-Z0-9_]*)\s*(?:\|\||\?\?)\s*["'`][^"'`]{2,}["'`]""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _JS_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*")):
                continue
            if "vigil: ignore" in line:
                continue
            m = self._PAT.search(line)
            if not m:
                continue
            var_name = m.group(1)
            if not _SENSITIVE_ENV.search(var_name):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"process.env.{var_name} falls back to a hardcoded string — credential baked into bundle when env var is unset",
                file_path=path,
                line=i,
                snippet=line.strip()[:120],
                fix=(
                    f"Remove the fallback: const {var_name.lower()} = process.env.{var_name}; "
                    f"then throw or exit early if it is undefined. "
                    "Hardcoded fallbacks end up in the compiled bundle and are visible "
                    "to anyone who inspects the JS output."
                ),
            ))
        return findings


# ── VGL-JS004 — eval() / new Function() in JS/TS ─────────────────────────────

class JsEvalNewFunctionRule(Rule):
    id = "VGL-JS004"
    name = "eval() or new Function() with dynamic argument (CWE-95)"
    severity = Severity.HIGH

    # new Function(...) — almost always risky
    _NEW_FUNC = re.compile(r"""\bnew\s+Function\s*\(""")

    # eval() where the argument is not a plain string literal
    # Matches eval( followed by anything that isn't an opening quote
    _EVAL_DYNAMIC = re.compile(r"""\beval\s*\(\s*(?!["'`])""")

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _JS_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []

        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("//", "*")):
                continue
            if "vigil: ignore" in line:
                continue

            if self._NEW_FUNC.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="new Function() constructs executable code at runtime — code injection if any argument is user-controlled",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Replace new Function() with a named function or a lookup map. "
                        "new Function(str) is equivalent to eval() — it parses and executes "
                        "arbitrary JavaScript, bypassing CSP script-src restrictions."
                    ),
                ))
            elif self._EVAL_DYNAMIC.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="eval() called with a dynamic argument — code injection if value is user-controlled",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Remove eval(). Use JSON.parse() for data, Function lookup tables for "
                        "dispatch, or import() for dynamic modules. "
                        "eval() with a variable executes arbitrary code and is blocked by strict CSP."
                    ),
                ))
        return findings
