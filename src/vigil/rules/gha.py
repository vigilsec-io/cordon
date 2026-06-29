"""
VGL-GHA001  CRITICAL  pull_request_target + fork ref checkout (Pwn Request)
VGL-GHA002  CRITICAL  User-controlled context expression in run: step (script injection → RCE)
VGL-GHA004  HIGH      ${{ secrets.X }} directly interpolated in run: step (visible in process table)
VGL-GHA005  MEDIUM    No permissions: block (implicit permissive GITHUB_TOKEN)
VGL-GHA006  HIGH      actions/cache in pull_request workflow (cache poisoning)
VGL-GHA007  HIGH      Self-hosted runner with pull_request trigger (persistent runner risk)
VGL-GHA008  HIGH      workflow_run trigger without head_branch/head_repository validation
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
