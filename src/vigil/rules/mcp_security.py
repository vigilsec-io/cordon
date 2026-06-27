"""VGL-MCP001–MCP003: MCP server security patterns.

MCP (Model Context Protocol) servers expose tools that AI models can call.
Three attack surfaces unique to this architecture:
  MCP001 — prompt injection baked into tool descriptions
  MCP002 — tool descriptions built from user-controlled data
  MCP003 — shell execution inside MCP tool handlers (no sandbox)
"""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_MCP_EXTS = {".py", ".ts", ".js"}

_MCP_SIGNAL = re.compile(
    r"(?:FastMCP|@mcp\.tool|@server\.tool|@server\.call_tool|mcp\.tool\(|"
    r"from\s+mcp\s+import|import\s+mcp\b|\"mcp\")",
)

# Injection keywords that should never appear in tool descriptions
_INJECT_PAT = re.compile(
    r"(?i)(?:ignore\s+(?:previous|above|prior|all)\s+(?:instruction|guideline|rule|constraint|request)|"
    r"disregard\s+(?:your|all|previous)|"
    r"you\s+are\s+now\s+(?:an?\s+)?(?:unrestricted|jailbreak|DAN)|"
    r"pretend\s+(?:you\s+are|to\s+be)|"
    r"act\s+as\s+(?:an?\s+)?(?:admin|root|unrestricted|evil|DAN|jailbreak)|"
    r"override\s+(?:your\s+)?(?:system\s+)?prompt|"
    r"new\s+instructions?:)",
)

_DESC_LINE = re.compile(r'description\s*=\s*["\'](.+)["\']')
_DESC_FSTRING = re.compile(
    r'description\s*=\s*f["\'][^"\']*\{[^}]*(?:request|user|input|param|query|message|data|body)\b',
)

_SHELL_PAT = re.compile(
    r"(?:subprocess\.(?:run|call|Popen|check_output)|os\.system|os\.popen)\s*\(",
)


class McpToolPoisoningRule(Rule):
    """VGL-MCP001: Prompt injection embedded in MCP tool description."""
    id = "VGL-MCP001"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _MCP_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _MCP_SIGNAL.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            m = _DESC_LINE.search(line)
            if m and _INJECT_PAT.search(m.group(1)):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="MCP tool description contains prompt injection instructions",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Tool descriptions must be static, factual, and free of instructions "
                        "to the model. Injection in descriptions poisons every agent that loads this tool."
                    ),
                ))
        return findings


class McpDynamicDescriptionRule(Rule):
    """VGL-MCP002: MCP tool description built from user-controlled data."""
    id = "VGL-MCP002"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _MCP_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _MCP_SIGNAL.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if _DESC_FSTRING.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="MCP tool description interpolates user-controlled data — injection vector",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Tool descriptions must be static strings defined at server startup. "
                        "Never interpolate request parameters, user input, or runtime data into descriptions."
                    ),
                ))
        return findings


class McpShellToolRule(Rule):
    """VGL-MCP003: Shell execution inside an MCP tool handler without sandbox."""
    id = "VGL-MCP003"
    severity = Severity.HIGH

    _SANDBOX = re.compile(
        r"(?:sandbox|chroot|seccomp|nsjail|firejail|docker\.run|allowlist|whitelist)",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _MCP_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _MCP_SIGNAL.search(text):
            return []
        if self._SANDBOX.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if _SHELL_PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Shell execution in MCP tool handler — no sandbox detected",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "MCP tools that execute shell commands must run in a sandbox "
                        "(Docker, nsjail, firejail) with a command allowlist. "
                        "An AI model controls the inputs — treat them as untrusted."
                    ),
                ))
        return findings
