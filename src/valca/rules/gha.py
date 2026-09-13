"""
VGL-GHA001  CRITICAL  pull_request_target + fork ref checkout (Pwn Request)
VGL-GHA002  CRITICAL  User-controlled context expression in run: step (script injection → RCE)
VGL-GHA004  HIGH      ${{ secrets.X }} directly interpolated in run: step (visible in process table)
VGL-GHA005  MEDIUM    No permissions: block (implicit permissive GITHUB_TOKEN)
VGL-GHA006  HIGH      actions/cache in pull_request workflow (cache poisoning)
VGL-GHA007  HIGH      Self-hosted runner with pull_request trigger (persistent runner risk)
VGL-GHA008  HIGH      workflow_run trigger without head_branch/head_repository validation
VGL-GHA009  CRITICAL  AI agent wired to untrusted-input trigger (issues/issue_comment/pull_request_target) + API key in env
VGL-GHA010  HIGH      AI agent on pull_request_target without fork origin guard
VGL-GHA011  CRITICAL  Untrusted GitHub event data (issue/PR/comment body) interpolated into an AI agent prompt
VGL-GHA012  HIGH      AI agent on untrusted trigger with no --allowedTools restriction
VGL-GHA013  MEDIUM    AI agent on untrusted trigger with no --max-turns limit
VGL-GHA014  HIGH      contents: write (or no permissions: block) with AI agent on untrusted trigger
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_GH_EXTS = {".yml", ".yaml"}
_GH_MARKER = re.compile(r"^(?:on|jobs)\s*:", re.MULTILINE)

# Run-block tracking: these keywords open/close a run: context
# Must handle both "run: |" and "- run: echo hi" (list-item form)
_RUN_OPEN = re.compile(r"^\s+(?:-\s+)?run\s*:")
_RUN_CLOSE = re.compile(r"^\s+(?:-\s+)?(?:uses|with|if|name|id|shell|working-directory)\s*:")
_ENV_ASSIGN = re.compile(r"^\s+\w[\w-]*\s*:\s*\$\{\{")

# ── Shared by the AI-agent rule family (VGL-GHA009, GHA011-014) ──────────────
# AI agent CLI invocations or known action slugs
_AI_AGENT = re.compile(
    r"""(?x)
    \bclaude\b          # Claude Code CLI
    | \bgemini\b        # Gemini CLI
    | anthropics?/claude-code-action
    | google-github-actions/gemini-cli-action
    | github/copilot-action
    | copilot-swe-agent
    """,
    re.IGNORECASE,
)

# Triggers that accept fully attacker-controlled content.
# Must end after the colon (no value on same line) to avoid matching
# permissions values like "issues: write".
_UNTRUSTED_TRIGGERS = re.compile(
    r"^\s*(?:issues|issue_comment|pull_request_target)\s*:\s*(?:#.*)?$",
    re.MULTILINE,
)

# AI API keys wired into the workflow environment
_AI_API_KEY = re.compile(
    r"ANTHROPIC_API_KEY|GEMINI_API_KEY|COPILOT_API_KEY|OPENAI_API_KEY",
    re.IGNORECASE,
)

_ALLOWED_TOOLS = re.compile(r"--allowed-?tools", re.IGNORECASE)


def _is_gha(path: Path, content: str) -> bool:
    if ".github" in str(path) and "workflow" in str(path).lower():
        return True
    return bool(_GH_MARKER.search(content))


# ── VGL-GHA001 — Pwn Request ──────────────────────────────────────────────────

class GhaPwnRequestRule(Rule):
    """pull_request_target + attacker-controlled fork ref checkout.
    Workflow runs with write access to production secrets while executing fork code."""

    id = "VGL-GHA001"
    name = "Pwn Request — pull_request_target with attacker-controlled checkout ref"
    severity = Severity.CRITICAL

    _PPT = re.compile(r"\bpull_request_target\b")
    _FORK_REF = re.compile(
        r"ref\s*:\s*\$\{\{.*github\.(?:head_ref|event\.pull_request\.head\.(?:sha|ref))\s*\}\}",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not self._PPT.search(content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if self._FORK_REF.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "Pwn Request: pull_request_target workflow checks out attacker-controlled fork code "
                        "— runs with write GITHUB_TOKEN and production secrets"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use the two-workflow pattern: (1) untrusted PR workflow saves artifacts, "
                        "(2) a workflow_run-triggered workflow consumes them with write permissions. "
                        "Never checkout github.event.pull_request.head.* in a pull_request_target workflow. "
                        "CVE-2025-61671 (CVSS 9.3) compromised Microsoft/Google/NVIDIA via this exact pattern."
                    ),
                ))
        return findings


# ── VGL-GHA002 — Script injection ────────────────────────────────────────────

class GhaScriptInjectionRule(Rule):
    """${{ github.event.pull_request.title }} etc. expanded BEFORE the shell sees the value.
    An attacker PR with a crafted title injects arbitrary shell commands."""

    id = "VGL-GHA002"
    name = "Script injection — user-controlled context expression in run: step"
    severity = Severity.CRITICAL

    _DANGEROUS = re.compile(
        r"""\$\{\{\s*github\.(?:
            event\.pull_request\.(?:title|body|head\.ref)|
            event\.issue\.(?:title|body)|
            event\.comment\.body|
            event\.label\.name|
            event\.commits\[0\]\.message|
            event\.workflow_run\.head_branch|
            head_ref|
            actor
        )\s*\}\}""",
        re.VERBOSE | re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []

        findings = []
        in_run = False
        for i, line in enumerate(content.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            if _RUN_OPEN.search(line):
                in_run = True
            elif _RUN_CLOSE.search(line):
                in_run = False
            if not in_run:
                continue
            if _ENV_ASSIGN.match(line):
                continue
            if self._DANGEROUS.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "Script injection — user-controlled context value in run: step; "
                        "attacker can inject shell commands via a crafted PR title/body/branch name"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use an intermediate env var: "
                        "'env:\\n  PR_TITLE: ${{ github.event.pull_request.title }}\\n"
                        "run: echo \"$PR_TITLE\"'. "
                        "Env vars are NOT expanded by ${{ }} — the shell sees the literal value, "
                        "blocking injection. The Nx attack (Aug 2025) used this vector."
                    ),
                ))
        return findings


# ── VGL-GHA004 — Secrets in run: step ────────────────────────────────────────

class GhaSecretsInRunRule(Rule):
    """${{ secrets.X }} directly interpolated in run: body.
    The secret value is written into the shell script text — visible in ps aux
    and potentially in debug/step-summary logs."""

    id = "VGL-GHA004"
    name = "Secret directly interpolated in run: step (visible in process table)"
    severity = Severity.HIGH

    _SECRET = re.compile(r"\$\{\{\s*secrets\.\w+\s*\}\}")

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []

        findings = []
        in_run = False
        for i, line in enumerate(content.splitlines(), 1):
            if line.lstrip().startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            if _RUN_OPEN.search(line):
                in_run = True
            elif _RUN_CLOSE.search(line):
                in_run = False
            if not in_run:
                continue
            if _ENV_ASSIGN.match(line):
                continue
            if self._SECRET.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "${{ secrets.X }} interpolated in run: step — "
                        "value written into shell script text, visible in process table and debug logs"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Pass the secret via a step-level env var: "
                        "'env:\\n  MY_SECRET: ${{ secrets.MY_SECRET }}\\n"
                        "run: curl -H \"Authorization: $MY_SECRET\"'. "
                        "Env vars keep the value out of the shell script text and process listing."
                    ),
                ))
        return findings


# ── VGL-GHA005 — Missing permissions block ────────────────────────────────────

class GhaMissingPermissionsRule(Rule):
    """No permissions: block — GITHUB_TOKEN uses the org/repo default,
    which may be permissive (write for contents, issues, pull-requests)."""

    id = "VGL-GHA005"
    name = "Workflow missing explicit permissions block (implicit GITHUB_TOKEN scope)"
    severity = Severity.MEDIUM

    _PERMISSIONS = re.compile(r"^\s*permissions\s*:", re.MULTILINE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if self._PERMISSIONS.search(content):
            return []

        return [Finding(
            rule_id=self.id,
            severity=self.severity,
            message=(
                "No permissions: block — GITHUB_TOKEN scope depends on org/repo default "
                "(often write for contents, issues, pull-requests)"
            ),
            file_path=path,
            line=1,
            snippet="(no permissions: block found in workflow)",
            fix=(
                "Add 'permissions: read-all' at the workflow top level and grant only the "
                "specific writes each job needs: "
                "permissions: {contents: read, pull-requests: write}. "
                "AI assistants almost never generate permissions blocks — "
                "Datadog 2026: 38% of orgs have at least one over-permissioned workflow."
            ),
        )]


# ── VGL-GHA006 — Cache poisoning ─────────────────────────────────────────────

class GhaCachePoisoningRule(Rule):
    """actions/cache in a pull_request workflow.
    Cache entries written by fork PR code are readable by base-branch release workflows,
    bridging the fork↔base trust boundary."""

    id = "VGL-GHA006"
    name = "Cache usage in pull_request workflow (cache poisoning attack vector)"
    severity = Severity.HIGH

    _PR_TRIGGER = re.compile(r"\bpull_request(?:_target)?\b")
    _CACHE = re.compile(r"actions/cache(?:/(?:restore|save))?@", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not self._PR_TRIGGER.search(content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if self._CACHE.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "actions/cache in pull_request workflow — "
                        "fork PR code can write poisoned cache entries read by trusted workflows"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Guard cache steps: "
                        "if: github.event.pull_request.head.repo.full_name == github.repository. "
                        "The TanStack attack (June 2026) used cache poisoning to bridge fork↔base "
                        "trust and extract OIDC tokens for npm package publication."
                    ),
                ))
        return findings


# ── VGL-GHA007 — Self-hosted runner on PR ────────────────────────────────────

class GhaSelfHostedOnPrRule(Rule):
    """Self-hosted runner in a pull_request-triggered workflow.
    Unlike ephemeral GitHub-hosted runners, self-hosted runners persist between jobs.
    Malicious PR code plants backdoors on the runner filesystem."""

    id = "VGL-GHA007"
    name = "Self-hosted runner with pull_request trigger (persistent runner risk)"
    severity = Severity.HIGH

    _PR_TRIGGER = re.compile(r"\bpull_request(?:_target)?\b")
    _SELF_HOSTED = re.compile(r"runs-on\s*:\s*(?:\[?\s*self-hosted)", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not self._PR_TRIGGER.search(content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if self._SELF_HOSTED.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "Self-hosted runner in pull_request workflow — "
                        "persistent filesystem accessible to attacker-controlled fork PR code"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Use ephemeral GitHub-hosted runners for PR workflows: runs-on: ubuntu-latest. "
                        "If self-hosted is required, use --ephemeral flag and run in a sandboxed environment. "
                        "Self-hosted runners persist state — a malicious PR can plant backdoors that "
                        "execute in subsequent trusted workflows on the same runner."
                    ),
                ))
        return findings


# ── VGL-GHA008 — workflow_run without ref validation ─────────────────────────

class GhaWorkflowRunNoRefRule(Rule):
    """workflow_run trigger without head_branch or head_repository validation.
    workflow_run executes in base context with secret access. Without validating
    the originating ref, fork-triggered CI chains into privileged workflows."""

    id = "VGL-GHA008"
    name = "workflow_run trigger without ref/repo validation"
    severity = Severity.HIGH

    _WR_TRIGGER = re.compile(r"^\s*workflow_run\s*:", re.MULTILINE)
    _REF_CHECK = re.compile(
        r"github\.event\.workflow_run\.(?:head_branch|head_repository)",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not self._WR_TRIGGER.search(content):
            return []
        if self._REF_CHECK.search(content):
            return []

        for i, line in enumerate(content.splitlines(), 1):
            if re.search(r"^\s*workflow_run\s*:", line):
                return [Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "workflow_run trigger without head_branch/head_repository validation — "
                        "fork-triggered CI can chain into this privileged workflow"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Add a ref guard: "
                        "if: github.event.workflow_run.head_branch == 'main' "
                        "AND github.event.workflow_run.head_repository.full_name == github.repository. "
                        "Without this, an attacker triggering the upstream workflow from a fork "
                        "gains access to production secrets and GITHUB_TOKEN in this workflow."
                    ),
                )]
        return []


# ── VGL-GHA009 — AI agent on untrusted-input trigger ─────────────────────────

class GhaAiAgentUntrustedTriggerRule(Rule):
    """VGL-GHA009 — AI coding agent wired to issues/issue_comment/pull_request_target
    while holding an AI API key in the environment.

    This is the exact architecture exploited in "Comment and Control" (April 2026,
    CVSS 9.4): attackers embed hidden instructions in HTML comments inside GitHub
    issues/PRs — invisible to human reviewers, fully parsed by the AI agent.
    The agent executes `ps auxeww | base64` and commits stolen credentials to a PR.

    Confirmed stolen in real attacks: ANTHROPIC_API_KEY, GITHUB_TOKEN,
    GEMINI_API_KEY, GITHUB_COPILOT_API_TOKEN, COPILOT_JOB_NONCE.
    """

    id = "VGL-GHA009"
    name = "AI agent wired to untrusted-input trigger (issues/pull_request_target) with API key in env"
    severity = Severity.CRITICAL

    # Mitigations that materially reduce blast radius — all three must be present
    # to downgrade from CRITICAL. Regex can't prove the guard logic is bulletproof
    # (e.g. a compromised collaborator still passes an author_association check),
    # so this downgrades the finding rather than suppressing it outright.
    _ACTOR_GUARD = re.compile(r"author_association", re.IGNORECASE)
    _SAFE_ROLES = re.compile(r"\b(?:OWNER|MEMBER|COLLABORATOR)\b")
    _READONLY_CONTENTS = re.compile(r"contents:\s*read\b", re.IGNORECASE)
    _WRITE_CONTENTS = re.compile(r"contents:\s*write\b", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not _UNTRUSTED_TRIGGERS.search(content):
            return []
        if not _AI_AGENT.search(content):
            return []
        if not _AI_API_KEY.search(content):
            return []

        mitigated = (
            self._ACTOR_GUARD.search(content) is not None
            and self._SAFE_ROLES.search(content) is not None
            and self._READONLY_CONTENTS.search(content) is not None
            and self._WRITE_CONTENTS.search(content) is None
            and _ALLOWED_TOOLS.search(content) is not None
        )
        severity = Severity.MEDIUM if mitigated else Severity.CRITICAL

        # Report on the first dangerous trigger line
        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if _UNTRUSTED_TRIGGERS.search(line):
                if mitigated:
                    return [Finding(
                        rule_id=self.id,
                        severity=severity,
                        message=(
                            "AI agent wired to untrusted-input trigger — actor guard, "
                            "read-only permissions, and restricted tool access are all present, "
                            "which substantially reduces blast radius"
                        ),
                        file_path=path,
                        line=i,
                        snippet=line.strip()[:120],
                        fix=(
                            "Mitigations detected (author_association guard, contents: read, "
                            "--allowedTools). This is advisory, not blocking — Vigil can't verify the "
                            "guard logic is bulletproof from static analysis alone (e.g. a compromised "
                            "collaborator account still passes an author_association check). Confirm the "
                            "guard covers every job that touches the API key, and that no step passes "
                            "github.event.issue.body directly into the agent prompt. "
                            "Reference: 'Comment and Control' (CVSS 9.4, April 2026)."
                        ),
                    )]
                return [Finding(
                    rule_id=self.id,
                    severity=severity,
                    message=(
                        "AI agent wired to untrusted-input trigger — "
                        "attacker can embed hidden instructions in issues/PRs (HTML comments, "
                        "invisible to humans) and hijack the agent to exfiltrate API keys via "
                        "ps auxeww|base64, bypassing GitHub secret scanning"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "1. Add actor guard: if: contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), "
                        "github.event.issue.author_association) — blocks external attacker issues from triggering. "
                        "2. Use --allowedTools to restrict agent to read-only operations. "
                        "3. Set permissions: {contents: read} — write GITHUB_TOKEN is not needed for review. "
                        "4. Never pass github.event.issue.body or PR titles directly into agent prompts. "
                        "Reference: 'Comment and Control' (CVSS 9.4, April 2026) — Claude Code, Gemini CLI, "
                        "and Copilot Agent all confirmed exploited via this pattern."
                    ),
                )]
        return []


# ── VGL-GHA010 — AI agent on pull_request_target without fork guard ───────────

class GhaAiAgentForkGuardRule(Rule):
    """VGL-GHA010 — AI agent triggered via pull_request_target without a fork
    origin check. pull_request_target runs with write GITHUB_TOKEN even for PRs
    from external forks. Without a guard, any stranger opening a PR auto-triggers
    the agent with full secret access and attacker-controlled content.

    Companion to VGL-GHA009 — specifically the pull_request_target variant,
    which is the most dangerous because it combines write scope + fork PRs.
    """

    id = "VGL-GHA010"
    name = "AI agent on pull_request_target without fork origin guard"
    severity = Severity.HIGH

    _PPT = re.compile(r"\bpull_request_target\b")
    # Fork origin guard patterns
    _FORK_GUARD = re.compile(
        r"""(?x)
        head\.repo(?:sitory)?\.full_name\s*==\s*github\.repository   # repo match
        | author_association                                           # role check
        | pull_request\.user\.login                                   # explicit user check
        """,
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not self._PPT.search(content):
            return []
        if not _AI_AGENT.search(content):
            return []
        if self._FORK_GUARD.search(content):
            return []  # guard is present

        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if re.search(r"\bpull_request_target\b", line):
                return [Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "AI agent on pull_request_target without fork origin guard — "
                        "any external contributor's PR auto-triggers the agent with write "
                        "GITHUB_TOKEN and attacker-controlled PR content"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Add a job-level if guard: "
                        "if: github.event.pull_request.head.repo.full_name == github.repository "
                        "|| contains(fromJSON('[\"OWNER\",\"MEMBER\",\"COLLABORATOR\"]'), "
                        "github.event.pull_request.author_association). "
                        "This prevents fork PRs from auto-triggering the agent. "
                        "For external PRs, require a maintainer to manually trigger the review "
                        "after inspecting the PR content."
                    ),
                )]
        return []


# ── VGL-GHA011 — Untrusted event data interpolated into AI agent prompt ──────

class GhaAiAgentPromptInjectionRule(Rule):
    """VGL-GHA011 — github.event.issue/pull_request/comment body or title flows
    into the same step that invokes an AI agent (inline string or env var).

    This is the actual data channel the Comment and Control attack exploits —
    more precise than VGL-GHA009's architecture-level check, since it confirms
    the untrusted content actually reaches the prompt rather than just co-existing
    with a dangerous trigger somewhere in the same file.
    """

    id = "VGL-GHA011"
    name = "Untrusted GitHub event data interpolated into AI agent prompt"
    severity = Severity.CRITICAL

    _EVENT_DATA = re.compile(
        r"""\$\{\{\s*github\.(?:
            event\.issue\.(?:title|body)|
            event\.pull_request\.(?:title|body|head\.ref)|
            event\.comment\.body
        )\s*\}\}""",
        re.VERBOSE | re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not _AI_AGENT.search(content):
            return []

        findings = []
        in_run = False
        run_start = 0
        buffer: list[str] = []

        def _flush() -> None:
            if not buffer:
                return
            blob = "\n".join(buffer)
            if not (_AI_AGENT.search(blob) and self._EVENT_DATA.search(blob)):
                return
            for offset, bline in enumerate(buffer):
                if self._EVENT_DATA.search(bline):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=(
                            "Untrusted GitHub event data flows into an AI agent prompt in this "
                            "step — an attacker-controlled issue/PR/comment body or title reaches "
                            "the agent, which is the exact channel 'Comment and Control' exploits"
                        ),
                        file_path=path,
                        line=run_start + offset,
                        snippet=bline.strip()[:120],
                        fix=(
                            "Never pass raw github.event.issue/pull_request/comment content "
                            "directly into an agent prompt or its env. If the agent needs the "
                            "content, sanitize it first (strip HTML comments, truncate, escape), "
                            "and restrict the agent with --allowedTools so even injected "
                            "instructions can't reach a shell."
                        ),
                    ))
                    break

        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if _RUN_OPEN.search(line):
                _flush()
                buffer = [line]
                run_start = i
                in_run = True
            elif _RUN_CLOSE.search(line):
                _flush()
                buffer = []
                in_run = False
            elif in_run:
                buffer.append(line)
        _flush()
        return findings


# ── VGL-GHA012 — AI agent on untrusted trigger with no --allowedTools ────────

class GhaAiAgentNoAllowedToolsRule(Rule):
    """VGL-GHA012 — companion to VGL-GHA009/GHA011. Without --allowedTools the
    agent keeps full shell access, so injected instructions can still run
    ps auxeww, read /proc/self/environ, or make network calls."""

    id = "VGL-GHA012"
    name = "AI agent on untrusted trigger with no --allowedTools restriction"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not _UNTRUSTED_TRIGGERS.search(content):
            return []
        if not _AI_AGENT.search(content):
            return []
        if not _AI_API_KEY.search(content):
            return []
        if _ALLOWED_TOOLS.search(content):
            return []

        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if _UNTRUSTED_TRIGGERS.search(line):
                return [Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "AI agent on untrusted trigger with no --allowedTools restriction — "
                        "the agent retains full shell access, so injected instructions can "
                        "still exfiltrate secrets even if other guards are bypassed"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        'Add --allowedTools "Read,Grep" (or the minimum the task needs) to the '
                        "agent invocation, and explicitly disallow Bash: "
                        '--disallowed-tools "Bash(*)". This removes the exfiltration path even '
                        "if an attacker's injected instructions do get read by the agent."
                    ),
                )]
        return []


# ── VGL-GHA013 — AI agent on untrusted trigger with no --max-turns ───────────

class GhaAiAgentNoMaxTurnsRule(Rule):
    """VGL-GHA013 — companion to VGL-GHA009/GHA012. Without --max-turns, an
    attacker's injected instructions can keep the agent running indefinitely —
    burning API quota or creating a time-based side channel."""

    id = "VGL-GHA013"
    name = "AI agent on untrusted trigger with no --max-turns limit"
    severity = Severity.MEDIUM

    _MAX_TURNS = re.compile(r"--max-turns", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not _UNTRUSTED_TRIGGERS.search(content):
            return []
        if not _AI_AGENT.search(content):
            return []
        if not _AI_API_KEY.search(content):
            return []
        if self._MAX_TURNS.search(content):
            return []

        for i, line in enumerate(content.splitlines(), 1):
            if "vigil: ignore" in line:
                continue
            if _UNTRUSTED_TRIGGERS.search(line):
                return [Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        "AI agent on untrusted trigger with no --max-turns limit — injected "
                        "instructions can keep the agent running indefinitely, burning API "
                        "quota or keeping the runner alive as a side channel"
                    ),
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Add --max-turns 10 (or whatever bounds the task) to the agent "
                        "invocation so injected instructions can't extend execution indefinitely."
                    ),
                )]
        return []


# ── VGL-GHA014 — contents:write with AI agent on untrusted trigger ───────────

class GhaAiAgentWritePermissionsRule(Rule):
    """VGL-GHA014 — companion to VGL-GHA005/GHA009. Even with an actor guard,
    contents: write (or no permissions: block, which often defaults to write)
    means a bypassed or buggy guard still leaves the commit+PR exfiltration
    path open. A review agent never needs write access to contents."""

    id = "VGL-GHA014"
    name = "contents: write permission with AI agent on untrusted trigger"
    severity = Severity.HIGH

    _PERMISSIONS_BLOCK = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
    _CONTENTS_WRITE = re.compile(r"^\s*contents\s*:\s*write\b", re.MULTILINE | re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gha(path, content):
            return []
        if not _UNTRUSTED_TRIGGERS.search(content):
            return []
        if not _AI_AGENT.search(content):
            return []
        if not _AI_API_KEY.search(content):
            return []

        write_match = self._CONTENTS_WRITE.search(content)
        has_permissions_block = self._PERMISSIONS_BLOCK.search(content) is not None
        if not write_match and has_permissions_block:
            return []  # explicit block present and it doesn't grant contents: write

        if write_match:
            line_no = content.count("\n", 0, write_match.start()) + 1
            snippet = write_match.group(0).strip()[:120]
        else:
            line_no = 1
            snippet = "(no permissions: block found — GITHUB_TOKEN may default to write)"

        return [Finding(
            rule_id=self.id,
            severity=self.severity,
            message=(
                "AI agent on untrusted trigger with contents: write permission (or no "
                "permissions: block at all) — if any guard is bypassed or buggy, the agent "
                "can still commit and open a PR to exfiltrate secrets"
            ),
            file_path=path,
            line=line_no,
            snippet=snippet,
            fix=(
                "Set permissions: {contents: read, issues: write} — a review agent only needs "
                "read access to contents and write access to post issue/PR comments. It never "
                "needs to push code."
            ),
        )]
