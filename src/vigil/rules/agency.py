"""VGL-A001–A004: Excessive agency — AI agents without human oversight.

These rules catch the patterns that make autonomous AI agents unsafe:
LLM output piped directly to shell, unbounded loops with no kill switch,
hardcoded auto-approval bypasses, and LLM content written to disk unchecked.
"""
from __future__ import annotations
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_AI_EXTS = {".py", ".ts", ".js"}

# Strips content from single- and double-quoted string literals so patterns
# like "auto_approve = True" in test fixture args don't trigger the rule.
_STRIP_STRINGS = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'')

_LLM_IMPORT = re.compile(
    r"(?:import|from|require)\s+.*(?:anthropic|openai|langchain|llama|cohere|mistral|google\.generativeai)",
    re.IGNORECASE,
)
_LLM_CALL = re.compile(
    r"(?:client\.messages\.create|openai\.chat\.completions|\.chat\.|llm\.invoke|llm\.run|chain\.run|agent\.run|model\.generate)",
)


class LlmShellExecRule(Rule):
    """VGL-A001: LLM output piped directly into shell execution."""
    id = "VGL-A001"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r"(?:subprocess\.(?:run|call|Popen)|os\.system|os\.popen)\s*\([^)]*"
        r"\b(?:response|completion|result|output|content|message)\b[^)]*\.(?:content|text|output)",
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(_STRIP_STRINGS.sub('""', line)):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="LLM output passed directly to shell — command injection risk",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Never pass LLM output directly to shell. Parse structured output, "
                        "validate against an allowlist, require human approval, or use a sandboxed executor."
                    ),
                ))
        return findings


class AutoApprovalBypassRule(Rule):
    """VGL-A002: Hardcoded auto-approval — disables human-in-the-loop gate."""
    id = "VGL-A002"
    severity = Severity.HIGH

    _PAT = re.compile(
        r"(?i)\b(auto_approve|skip_approval|bypass_approval|approve_all|skip_confirmation|skip_review)\s*=\s*True",
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith("#"):  # commented-out code is not live code
                continue
            if self._PAT.search(_STRIP_STRINGS.sub('""', line)):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Auto-approval hardcoded — HITL gate bypassed: {stripped[:60]}",
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix=(
                        "Require explicit human approval for agent actions. Read approval state "
                        "from SSM or a runtime flag — never hardcode True in source."
                    ),
                ))
        return findings


class UnboundedAgentLoopRule(Rule):
    """VGL-A003: Unbounded agentic loop — while True with LLM calls, no iteration limit."""
    id = "VGL-A003"
    severity = Severity.HIGH

    _WHILE_TRUE = re.compile(r"^\s*while\s+True\s*:")
    _ITER_LIMIT = re.compile(
        r"\b(max_iterations|max_turns|max_steps|max_loops|iteration_limit|step_limit)\b",
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []

        # Only flag when the file actually makes LLM calls
        if not _LLM_IMPORT.search(text) and not _LLM_CALL.search(text):
            return []
        if self._ITER_LIMIT.search(text):
            return []

        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines, 1):
            if self._WHILE_TRUE.match(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Unbounded 'while True' loop with LLM calls — no iteration limit found",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix=(
                        "Add max_iterations and a kill-switch check at the top of the loop. "
                        "Read the kill switch from SSM so it can be toggled without a deploy."
                    ),
                ))
        return findings


class LlmOutputFileWriteRule(Rule):
    """VGL-A004: LLM response written directly to disk without validation."""
    id = "VGL-A004"
    severity = Severity.HIGH

    _PAT = re.compile(
        r"(?:write_text|\.write)\s*\([^)]*\b(?:llm_output|ai_output|model_output|"
        r"response\.content|completion\.content|message\.content|result\.text)\b",
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            if self._PAT.search(_STRIP_STRINGS.sub('""', line)):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="LLM output written to filesystem without validation",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Validate and sanitize LLM output before writing to disk. "
                        "Consider schema validation, content-type checks, or a human review step."
                    ),
                ))
        return findings
