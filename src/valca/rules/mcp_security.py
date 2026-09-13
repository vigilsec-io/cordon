"""VGL-MCP001–MCP005: MCP server security patterns.

MCP (Model Context Protocol) servers expose tools that AI models can call.
Attack surfaces unique to this architecture:
  MCP001 — prompt injection baked into tool descriptions
  MCP002 — tool descriptions built from user-controlled data
  MCP003 — shell execution inside MCP tool handlers (no sandbox)
  MCP004 — unpinned/HTTP MCP server endpoint config (rug pull surface)
  MCP005 — SSRF via an MCP fetch/http_request tool with no URL validation
"""
from __future__ import annotations
import json
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
    name = "Prompt injection embedded in MCP tool description"
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
    name = "MCP tool description built from user-controlled data"
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
    name = "Shell execution in an MCP tool handler without a sandbox"
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


# ── VGL-MCP004 — Unpinned or HTTP MCP server endpoint config ─────────────────

_MCP_CONFIG_FILENAMES = {"mcp.json", "claude_desktop_config.json", "settings.json"}


def _npx_arg_has_version_pin(arg: str) -> bool:
    """True if the last '@' in the arg is followed by a version, not '@latest'."""
    at_positions = [i for i, c in enumerate(arg) if c == "@"]
    if not at_positions:
        return False
    version_part = arg[at_positions[-1] + 1 :]
    if version_part.lower() == "latest":
        return False
    return bool(re.match(r"\d+(?:\.\d+)*", version_part))


class McpUnpinnedOrHttpEndpointRule(Rule):
    """VGL-MCP004: MCP server config uses an unpinned npx package (silent
    rug-pull update surface — postmark-mcp, Sep 2025) or a plaintext HTTP
    endpoint (MITM + silent swap)."""

    id = "VGL-MCP004"

    name = "MCP server config uses an unpinned package or plaintext HTTP endpoint"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        name = path.name.lower()
        if name in _MCP_CONFIG_FILENAMES:
            return True
        return path.suffix == ".json" and ".mcp" in path.parts

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
            data = json.loads(text)
        except (OSError, ValueError):
            return []
        if not isinstance(data, dict):
            return []

        servers = data.get("mcpServers")
        if not isinstance(servers, dict):
            if all(isinstance(v, dict) for v in data.values()) and data:
                servers = data
            else:
                return []

        lines = text.splitlines()
        findings = []
        for name, conf in servers.items():
            if not isinstance(conf, dict):
                continue
            line_no = next((i + 1 for i, l in enumerate(lines) if f'"{name}"' in l), 1)

            url = conf.get("url")
            if isinstance(url, str) and url.startswith("http://"):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        f"MCP server '{name}' uses a plaintext HTTP endpoint — "
                        "MITM and silent endpoint swap risk"
                    ),
                    file_path=path,
                    line=line_no,
                    snippet=f'"url": "{url}"'[:120],
                    fix="Use https:// for the MCP server endpoint.",
                ))
                continue

            if conf.get("command") == "npx":
                args = conf.get("args", [])
                pkg_arg = next(
                    (a for a in args if isinstance(a, str) and not a.startswith("-")), None,
                )
                if pkg_arg and not _npx_arg_has_version_pin(pkg_arg):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=(
                            f"MCP server '{name}' runs an unpinned npx package — a silent "
                            "maintainer update becomes a silent rug pull with no re-approval"
                        ),
                        file_path=path,
                        line=line_no,
                        snippet=pkg_arg[:120],
                        fix=(
                            f"Pin to an exact version: \"{pkg_arg}@X.Y.Z\" instead of "
                            "an unpinned or @latest reference."
                        ),
                    ))
        return findings


# ── VGL-MCP005 — SSRF via MCP fetch/http_request tool ─────────────────────────

_TOOL_FUNC_DEF = re.compile(
    r"def\s+(fetch|http_request|web_request|browse|navigate|open_url|request_url|call_api)\w*\s*\(([^)]*)\)",
    re.IGNORECASE,
)
_HTTP_CALL = re.compile(
    r"httpx\.\w+\(|requests\.\w+\(|urllib\.request\.\w+\(|aiohttp\.",
)
_URL_ALLOWLIST_CHECK = re.compile(
    r"allowlist|allowed|whitelist|startswith|urlparse|\.netloc\b",
    re.IGNORECASE,
)


def _function_body(lines: list[str], def_line_idx: int) -> list[str]:
    def_line = lines[def_line_idx]
    def_indent = len(def_line) - len(def_line.lstrip())
    body = []
    for line in lines[def_line_idx + 1 :]:
        if line.strip() == "":
            body.append(line)
            continue
        indent = len(line) - len(line.lstrip())
        if indent <= def_indent:
            break
        body.append(line)
    return body


class McpSsrfFetchToolRule(Rule):
    """VGL-MCP005: An MCP tool exposing a fetch/http_request-style function
    with an agent-controllable url parameter, and no allowlist check before
    making the request — SSRF via prompt injection (36.7% of tested MCP
    servers vulnerable, MCP Security Statistics 2026)."""

    id = "VGL-MCP005"

    name = "MCP fetch tool takes an agent-controlled URL with no allowlist"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".py"

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _MCP_SIGNAL.search(text):
            return []

        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            m = _TOOL_FUNC_DEF.search(line)
            if not m:
                continue
            params = m.group(2)
            if "url" not in params:
                continue
            body = _function_body(lines, i)
            body_text = "\n".join(body)
            if not _HTTP_CALL.search(body_text):
                continue
            if _URL_ALLOWLIST_CHECK.search(body_text):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "MCP tool accepts an agent-controllable URL and makes an HTTP request "
                    "with no allowlist check — an attacker who achieves prompt injection can "
                    "reach internal network/cloud metadata endpoints (SSRF)"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Validate the URL against an explicit allowlist before making the request: "
                    "if not any(url.startswith(a) for a in allowed): raise ValueError(...). "
                    "Never let the agent's input reach the network client unchecked."
                ),
            ))
        return findings
