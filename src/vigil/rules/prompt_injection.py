"""VGL-PI001–PI004: Prompt injection vulnerabilities in AI-calling code.

These rules catch code patterns where untrusted user input reaches an LLM
context without sanitization — the server-side prompt injection surface.
"""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_AI_EXTS = {".py", ".ts", ".js"}

_LLM_SIGNAL = re.compile(
    r"(?:anthropic|openai|langchain|llama_index|cohere|mistral|google\.generativeai|"
    r"client\.messages|chat\.completions|llm\.invoke|ChatOpenAI|ChatAnthropic)",
)

# User-controlled variable names — common across all PI rules
_USER_INPUT = r"(?:user_input|user_query|user_message|user_prompt|user_content|" \
              r"request\.(?:body|data|json|text|form|args|params|get|post)|" \
              r"\binput\b|\bquery\b|\bprompt\b|\buser_text\b)"


class UserInputInSystemPromptRule(Rule):
    """VGL-PI001: User input interpolated directly into the LLM system prompt."""
    id = "VGL-PI001"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r'["\']?system["\']?\s*[:=]\s*f["\'][^"\']*\{[^}]*' + _USER_INPUT,
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="User input interpolated into LLM system prompt — prompt injection risk",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Never interpolate user-controlled data into the system prompt. "
                        "Keep the system prompt static. Pass user input only in the 'user' role message, "
                        "and sanitize it before use (strip special tokens, enforce length limits)."
                    ),
                ))
        return findings


class RawRequestAsLlmContentRule(Rule):
    """VGL-PI002: Raw HTTP request body used as LLM message content."""
    id = "VGL-PI002"
    severity = Severity.HIGH

    _PAT = re.compile(
        r'["\']content["\']?\s*[:=]\s*(?:request\.(?:body|data|json|text|form)|'
        r'f["\'][^"\']*\{[^}]*request\.[^}]+\})',
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Raw HTTP request content passed to LLM without sanitization",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Extract and validate the specific fields you need from the request. "
                        "Enforce length limits, strip control characters, and reject "
                        "inputs containing LLM special tokens (<|system|>, [INST], etc.)."
                    ),
                ))
        return findings


class TemplateInjectionInPromptRule(Rule):
    """VGL-PI003: str.format() or % formatting used to build LLM prompts with user data."""
    id = "VGL-PI003"
    severity = Severity.HIGH

    _PAT = re.compile(
        r'(?:system_prompt|system_message|base_prompt|SYSTEM_PROMPT)\s*=\s*'
        r'["\'][^"\']+["\']\.format\s*\(',
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="str.format() used to build LLM system prompt — injection if user-controlled args",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use only static system prompts. If dynamic content is required, "
                        "use a structured data injection approach (JSON block in user turn) "
                        "rather than string formatting into the system role."
                    ),
                ))
        return findings


class UnsanitizedToolOutputRule(Rule):
    """VGL-PI004: Tool/function output appended to conversation without sanitization."""
    id = "VGL-PI004"
    severity = Severity.MEDIUM

    _PAT = re.compile(
        r'(?:messages|conversation|chat_history|history)\s*\.\s*append\s*\('
        r'[^)]*["\'](?:tool|function)["\']',
    )
    _SANITIZE = re.compile(
        r"(?:sanitize|clean|validate|strip_tags|escape|bleach|html\.escape)",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        # If there's sanitization in the file, give benefit of the doubt
        if self._SANITIZE.search(text):
            return []
        findings = []
        for i, line in enumerate(text.splitlines(), 1):
            if self._PAT.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Tool output appended to conversation without visible sanitization",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Sanitize tool/function output before injecting into the conversation. "
                        "External tool responses may contain adversarial content designed to "
                        "hijack subsequent model turns (indirect prompt injection)."
                    ),
                ))
        return findings
