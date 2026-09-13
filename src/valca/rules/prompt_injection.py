"""VGL-PI001–PI009: Prompt injection vulnerabilities in AI-calling code.

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

# Shared by PI005-009 — the actual LLM invocation call, as opposed to
# _LLM_SIGNAL which just detects an LLM library is used somewhere in the file.
_LLM_CALL = re.compile(
    r"\.messages\.create|\.chat\.completions\.create|\.complete\s*\(|llm\.invoke|"
    r"ChatOpenAI\s*\(|ChatAnthropic\s*\(|client\.generate_content|agent\.run\s*\(",
    re.IGNORECASE,
)


class UserInputInSystemPromptRule(Rule):
    """VGL-PI001: User input interpolated directly into the LLM system prompt."""
    id = "VGL-PI001"
    name = "User input interpolated into the LLM system prompt"
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
    name = "Raw HTTP request body used as LLM message content"
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
    name = "String formatting used to build prompts with user data"
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
    name = "Tool output appended to the conversation without sanitization"
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


# ── VGL-PI005 — HTTP request data interpolated into AI prompt (app-level) ────

class HttpRequestDataInPromptRule(Rule):
    """VGL-PI005: HTTP request data (query/body/form/headers) flows into an
    LLM call within a few lines — the same attack class as Comment and
    Control, at the application layer instead of CI/CD."""

    id = "VGL-PI005"

    name = "HTTP request data flows into an LLM prompt unsanitised"
    severity = Severity.CRITICAL

    _REQUEST_DATA = re.compile(
        r"request\.(?:json|body|form|args|params|POST|GET)|req\.(?:body|query|params)",
        re.IGNORECASE,
    )
    _WINDOW = 6

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if not self._REQUEST_DATA.search(line):
                continue
            window = lines[i : i + self._WINDOW]
            if not any(_LLM_CALL.search(w) for w in window):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "HTTP request data flows into an AI prompt — attacker-controlled "
                    "request content can inject instructions the model will follow"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Never interpolate raw request data into a prompt. Extract only the "
                    "specific fields you need, enforce length limits, and keep a strict role "
                    "separation: user-provided content goes in the 'user' turn as data, never "
                    "in a system prompt or as instructions."
                ),
            ))
        return findings


# ── VGL-PI006 — AI output piped to subprocess/exec/eval ──────────────────────

class LlmOutputToExecRule(Rule):
    """VGL-PI006: LLM response content flows into subprocess/exec/eval without
    validation — the execution half of the injection→execution chain."""

    id = "VGL-PI006"

    name = "LLM response flows into subprocess, exec or eval"
    severity = Severity.CRITICAL

    _DANGEROUS_SINK = re.compile(
        r"subprocess\.run\([^)]*shell\s*=\s*True|os\.system\s*\(|"
        r"(?<!\.)\beval\s*\(|(?<!\.)\bexec\s*\(|child_process\.exec\s*\(|execSync\s*\(",
    )
    _LLM_RESPONSE_ACCESSOR = re.compile(
        r"\.content\[0\]\.text|response\.text|\.completion\b|choices\[0\]\.message\.content",
        re.IGNORECASE,
    )
    _WINDOW = 8

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if not self._DANGEROUS_SINK.search(line):
                continue
            if self._LLM_RESPONSE_ACCESSOR.search(line):
                pass  # direct: eval(result.content[0].text)
            else:
                back = lines[max(0, i - self._WINDOW) : i]
                if not any(self._LLM_RESPONSE_ACCESSOR.search(b) for b in back):
                    continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "AI model output flows into subprocess/exec/eval without validation — "
                    "an attacker who controls the model's input can craft a response that "
                    "runs arbitrary commands on the host"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Never pass LLM output to a shell or eval. Parse the response as "
                    "structured data (JSON, a specific schema), validate it, and take only "
                    "the explicitly expected action."
                ),
            ))
        return findings


# ── VGL-PI007 — Webhook payload passed directly to AI agent ──────────────────

class WebhookPayloadToAgentRule(Rule):
    """VGL-PI007: A webhook/API payload field flows directly into an AI agent
    constructor or run() call — any service that can send you a webhook
    becomes a prompt injection vector."""

    id = "VGL-PI007"

    name = "Webhook payload flows directly into an AI agent"
    severity = Severity.HIGH

    # Root object + field name checked independently (not adjacency) so nested
    # access like payload["pull_request"]["title"] still matches — the root
    # and the leaf field name can be separated by intermediate keys.
    _PAYLOAD_ROOT = re.compile(r"\b(?:payload|event|data|body)\b", re.IGNORECASE)
    _FIELD_NAME_ACCESS = re.compile(
        r"""(?:\.get\(\s*|\[\s*)["']?(?:title|body|text|message|description|content)["']?""",
        re.IGNORECASE,
    )
    _AGENT_INVOCATION = re.compile(
        r"\bAgent\s*\(|\.run\s*\(|agent\.(?:run|invoke)\s*\(",
    )
    _WINDOW = 4

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if not (self._PAYLOAD_ROOT.search(line) and self._FIELD_NAME_ACCESS.search(line)):
                continue
            window = lines[i : i + self._WINDOW]
            if not any(self._AGENT_INVOCATION.search(w) for w in window):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "Webhook/API payload field flows directly into an AI agent without a "
                    "sanitization layer — PR titles, Slack messages, and similar free-text "
                    "webhook fields are attacker-controlled"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Extract only the specific, typed fields you need. Never pass the full "
                    "payload body or a free-text field straight into an agent's task. Treat "
                    "webhook content as untrusted data, the same as any other user input."
                ),
            ))
        return findings


# ── VGL-PI008 — Second-order injection via DB-sourced content ────────────────

class DbContentInPromptRule(Rule):
    """VGL-PI008: A database field (ORM result or raw SQL row) is interpolated
    into an LLM prompt. Second-order injection — the poisoned content was
    written via a normal user path (bio, note, document) at an earlier,
    unrelated time, so the read-time code looks safe on its own."""

    id = "VGL-PI008"

    name = "Database content interpolated into a prompt — second-order injection"
    severity = Severity.HIGH

    _DB_QUERY_SIGNAL = re.compile(
        r"\.query\(|db\.execute\(|\.filter_by\(|\.filter\(|cursor\.fetch|"
        r"\.first\(\)|SELECT\s+.+\s+FROM",
        re.IGNORECASE,
    )
    # An f-string interpolating a field access (obj.attr or row["key"]) —
    # distinguishes "database row field" from a plain variable (VGL-PI001's
    # territory).
    _FSTRING_FIELD_ACCESS = re.compile(
        r"""f["'][^"']*\{\s*\w+(?:\.\w+|\[[^\]]+\])+\s*\}""",
    )
    _BACKWARD_WINDOW = 10
    _FORWARD_WINDOW = 6

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not _LLM_SIGNAL.search(text):
            return []
        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if not self._FSTRING_FIELD_ACCESS.search(line):
                continue
            back = lines[max(0, i - self._BACKWARD_WINDOW) : i]
            fwd = lines[i : i + self._FORWARD_WINDOW]
            if not any(self._DB_QUERY_SIGNAL.search(b) for b in back):
                continue
            if not any(_LLM_CALL.search(w) for w in fwd):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "Database-sourced content is interpolated into an AI prompt — content "
                    "written via a normal user flow earlier (profile bio, note, document) "
                    "can carry injected instructions that execute when the agent reads it"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Treat database string fields as untrusted input, not safe internal "
                    "data. Wrap DB content in structural delimiters and add explicit "
                    "'the following is untrusted data' framing in the system prompt."
                ),
            ))
        return findings


# ── VGL-PI009 — User input flowing into vector store write ───────────────────

class UserInputToVectorStoreRule(Rule):
    """VGL-PI009: User-controlled input is written directly into a vector
    store / RAG database — memory poisoning (OWASP ASI06). The attacker's
    input executes as instructions in a completely different, later session
    with no visible connection back to them."""

    id = "VGL-PI009"

    name = "User input written into a vector store — memory poisoning"
    severity = Severity.HIGH

    _VECTORSTORE_IMPORT = re.compile(
        r"^\s*(?:import|from)\s+chromadb\b|^\s*(?:import|from)\s+pinecone\b|"
        r"^\s*(?:import|from)\s+weaviate\b|\bqdrant_client\b|"
        r"from\s+langchain[.\w]*\.vectorstores",
        re.IGNORECASE | re.MULTILINE,
    )
    _VECTORSTORE_WRITE = re.compile(
        r"\.add\s*\(|\.upsert\s*\(|\.add_texts\s*\(|\.data_object\.create\s*\(",
    )
    _REQUEST_LIKE = re.compile(
        r"request\.(?:json|body|form|POST|GET|args|params)|form\.cleaned_data|"
        r"payload\[|event\[",
        re.IGNORECASE,
    )
    _WINDOW = 3

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _AI_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="ignore")
        except OSError:
            return []
        if not self._VECTORSTORE_IMPORT.search(text):
            return []
        lines = text.splitlines()
        findings = []
        for i, line in enumerate(lines):
            if not self._VECTORSTORE_WRITE.search(line):
                continue
            window = lines[max(0, i - self._WINDOW) : i + 1]
            if not any(
                re.search(_USER_INPUT, w) or self._REQUEST_LIKE.search(w)
                for w in window
            ):
                continue
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=(
                    "User-controlled input is written directly into a vector store — "
                    "an attacker's content persists and executes as instructions when an "
                    "AI agent later reads it back, in a session with no link to the attacker"
                ),
                file_path=path,
                line=i + 1,
                snippet=line.strip()[:120],
                fix=(
                    "Wrap user content in a structural delimiter that signals 'this is data, "
                    "not an instruction' before writing to the vector store, or keep "
                    "user-sourced vectors in a separate namespace from trusted/system vectors. "
                    "Reference: OWASP ASI06 (memory poisoning)."
                ),
            ))
        return findings
