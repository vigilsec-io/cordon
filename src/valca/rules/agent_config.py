"""VGL-AGENT001–AGENT002: AI agent configuration and framework security.

Distinct from VGL-A001-004 (agency.py, excessive-agency code patterns) —
these rules cover agent *config files* (CLAUDE.md, copilot-instructions.md)
and *framework* pitfalls (credential exposure through exception handling).
"""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_AGENT_CONFIG_FILENAMES = {"claude.md", "agent.md", "copilot-instructions.md"}

# Domains that commonly appear in legitimate install/setup instructions —
# the one false-positive guard, not code-fence detection. A malicious
# instruction hidden in a fence is just as dangerous as one in plain prose,
# so fencing alone doesn't grant immunity.
_SAFE_INSTALL_DOMAINS = re.compile(
    r"github\.com|githubusercontent\.com|homebrew\.sh|brew\.sh|npmjs\.com|"
    r"pypi\.org|python\.org|nodejs\.org|anthropic\.com",
    re.IGNORECASE,
)

_DANGEROUS_AGENT_INSTRUCTION = re.compile(
    r"""(?x)
    \bcurl\s+https?://    |
    \bwget\s+https?://    |
    \bbash\s+-c\b         |
    \bsh\s+-c\b           |
    \bnc\s+-e\b           |
    \bncat\b              |
    python3?\s+-c\b       |
    ruby\s+-e\b           |
    perl\s+-e\b           |
    \|\s*base64\b         |
    base64\s+-            |
    >\s*/tmp/             |
    cat\s+~?/\.ssh        |
    env\s*\|\s*grep       |
    \bprintenv\b          |
    ps\s+auxeww           |
    (?:export\s+|set\s+)?ANTHROPIC_BASE_URL |
    /dev/tcp/             |
    \bmkfifo\b
    """,
    re.IGNORECASE,
)


class DangerousAgentConfigInstructionRule(Rule):
    """VGL-AGENT001: Shell exec / exfiltration instructions embedded in an
    agent config file (CLAUDE.md, copilot-instructions.md, etc).

    CVE-2025-59536: Claude Code reads these files before any trust dialog —
    a malicious CLAUDE.md in an otherwise-clean repo can execute on open,
    with no code in the repo itself for review to catch. HTML comments
    (invisible in GitHub's rendered UI) are the primary hiding spot, so
    this rule does NOT skip comments or fenced code blocks — both are
    read identically by the agent.
    """

    id = "VGL-AGENT001"

    name = "Shell execution or exfiltration instructions in an AI agent config file"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        name = path.name.lower()
        if name in _AGENT_CONFIG_FILENAMES:
            return True
        if path.suffix == ".md" and (".claude" in path.parts or ".github" in path.parts):
            return True
        return False

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if not _DANGEROUS_AGENT_INSTRUCTION.search(line):
                continue
            if _SAFE_INSTALL_DOMAINS.search(line):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "Agent config file contains a shell exec / exfiltration / credential-"
                    "harvesting instruction — executes before any trust dialog when an agent "
                    "opens this project (CVE-2025-59536)"
                ),
                file_path=path,
                line=i,
                snippet=line.strip()[:120],
                fix=(
                    "Remove executable shell instructions from agent config files. If this "
                    "is a legitimate install/setup command, reference a documented, pinned "
                    "install script instead of an inline shell command an agent could execute "
                    "unattended. Check HTML comments too — they're invisible in rendered "
                    "Markdown but fully read by the agent."
                ),
            ))
        return findings


_AGENT_FRAMEWORK_IMPORT = re.compile(
    r"^\s*(?:import|from)\s+(?:crewai|langchain|autogen)\b",
    re.MULTILINE | re.IGNORECASE,
)
_SECRET_ATTR_NAME = re.compile(
    r"\w*(?:api_key|token|secret|password|credential|auth)\w*",
    re.IGNORECASE,
)
_HEADERS_DUMP = re.compile(r"\.headers\b", re.IGNORECASE)
_GENERIC_OBJECT_DUMP = re.compile(
    r"vars\(\s*self\s*\)|self\.__dict__|self\.config\b|self\.state\b",
)
_EXCEPT_LINE = re.compile(r"^\s*except\b")


class AgentExceptionCredentialExposureRule(Rule):
    """VGL-AGENT002: Credential exposure through an exception handler in
    agent framework code — the CrewAI 'Uncrew' pattern (Nov 2025). A secret
    held by self (api_key, token, etc.) travels with the exception when the
    handler logs, raises, or returns the full object/headers instead of a
    scrubbed message.
    """

    id = "VGL-AGENT002"

    name = "Credentials exposed through an exception handler in agent code"
    severity = Severity.HIGH

    _WINDOW = 6

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".py"

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _AGENT_FRAMEWORK_IMPORT.search(text):
            return []
        has_secret_context = bool(_SECRET_ATTR_NAME.search(text))

        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if "vigil: ignore" in line:
                continue
            if not _EXCEPT_LINE.match(line):
                continue
            window = lines[i : i + self._WINDOW]
            for offset, w in enumerate(window):
                exposes_directly = _SECRET_ATTR_NAME.search(w) or _HEADERS_DUMP.search(w)
                exposes_via_dump = has_secret_context and _GENERIC_OBJECT_DUMP.search(w)
                if not (exposes_directly or exposes_via_dump):
                    continue
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "Exception handler exposes credentials — a secret-holding attribute, "
                        "request headers, or the full object state is logged, raised, or "
                        "returned instead of a scrubbed error message"
                    ),
                    file_path=path,
                    line=i + offset + 1,
                    snippet=w.strip()[:120],
                    fix=(
                        "Never include self.__dict__, vars(self), self.config, self.state, or "
                        "request/response headers in an exception message, log call, or returned "
                        "error object. Build a scrubbed error message that names only the failed "
                        "operation, not the credentials used to attempt it."
                    ),
                ))
                break
        return findings
