"""
VGL-GH001  HIGH      GitHub Actions secret value printed in a run: step (log exposure)
VGL-GH002  HIGH      GitHub Actions workflow with write-all or over-broad permissions
VGL-GH003  HIGH      GitHub Actions uses a mutable action ref (tag/branch instead of SHA)
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_GH_EXTS = {".yml", ".yaml"}

# Fast check: is this file a GitHub Actions workflow?
_GH_MARKER = re.compile(r"^(?:on|jobs)\s*:", re.MULTILINE)


def _is_gh_actions(path: Path, content: str) -> bool:
    """True if the file looks like a GitHub Actions workflow."""
    if ".github" in str(path) and "workflow" in str(path):
        return True
    return bool(_GH_MARKER.search(content))


# ── VGL-GH001 — Secret exposed in run: step ──────────────────────────────────

class GhActionsSecretInRunRule(Rule):
    id = "VGL-GH001"
    name = "GitHub Actions secret printed in run step (log exposure)"
    severity = Severity.HIGH

    # Single-line: run: echo ${{ secrets.X }} or run: curl -H "Authorization: ${{ secrets.TOKEN }}"
    _RUN_SECRET = re.compile(
        r"run\s*:.*\$\{\{\s*secrets\.",
        re.IGNORECASE,
    )
    # Multi-line pipe blocks: lines starting with pipe content after a run: |
    # These often contain: echo ${{ secrets.X }}
    _INLINE_SECRET = re.compile(
        r"(?:echo|curl|wget|printf|cat|export)[^#\n]*\$\{\{\s*secrets\.",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gh_actions(path, content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            if self._RUN_SECRET.search(line) or self._INLINE_SECRET.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="GitHub Actions secret referenced in a run step — value will appear in workflow logs",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Pass secrets via environment variables, not inline: "
                        "set env: MY_SECRET: ${{ secrets.MY_SECRET }} at the step level, "
                        "then reference $MY_SECRET in the run: block. "
                        "This avoids the value appearing in the rendered log lines."
                    ),
                ))
        return findings


# ── VGL-GH002 — Excessive permissions ────────────────────────────────────────

class GhActionsExcessivePermissionsRule(Rule):
    id = "VGL-GH002"
    name = "GitHub Actions workflow with excessive permissions"
    severity = Severity.HIGH

    _WRITE_ALL = re.compile(r"permissions\s*:\s*write-all", re.IGNORECASE)
    # Broad write grants at workflow or job level
    _CONTENTS_WRITE = re.compile(r"contents\s*:\s*write", re.IGNORECASE)
    _PACKAGES_WRITE = re.compile(r"packages\s*:\s*write", re.IGNORECASE)
    _ID_TOKEN_WRITE = re.compile(r"id-token\s*:\s*write", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gh_actions(path, content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            if (
                self._WRITE_ALL.search(line)
                or self._CONTENTS_WRITE.search(line)
                or self._PACKAGES_WRITE.search(line)
                or self._ID_TOKEN_WRITE.search(line)
            ):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="GitHub Actions workflow grants broad write permissions — least-privilege violation",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Set permissions: read-all at the top level and grant only the "
                        "specific write permission each job needs. "
                        "Broad write access lets a compromised step push code, modify packages, "
                        "or obtain OIDC tokens for cloud provider access."
                    ),
                ))
        return findings


# ── VGL-GH003 — Unpinned action ref ──────────────────────────────────────────

class GhActionsUnpinnedActionRule(Rule):
    id = "VGL-GH003"
    name = "GitHub Actions uses mutable action ref (tag or branch)"
    severity = Severity.HIGH

    # Matches: uses: owner/action@ref
    _USES = re.compile(r"uses\s*:\s*(\S+@\S+)", re.IGNORECASE)
    # A pinned SHA: 7–40 hex chars
    _PINNED_SHA = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _GH_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []
        if not _is_gh_actions(path, content):
            return []

        findings = []
        for i, line in enumerate(content.splitlines(), 1):
            stripped = line.lstrip()
            if stripped.startswith("#"):
                continue
            if "vigil: ignore" in line:
                continue
            m = self._USES.search(line)
            if not m:
                continue
            ref = m.group(1).rsplit("@", 1)[-1].split()[0].rstrip("\"'")
            if not self._PINNED_SHA.match(ref):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"Action uses mutable ref '@{ref}' — a tag or branch that can be silently updated",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        f"Pin to a full commit SHA: uses: {m.group(1).rsplit('@', 1)[0]}@<sha>  # {ref}\n"
                        "Find the SHA: on GitHub → the action's repo → the tag → copy the commit SHA. "
                        "Mutable tags are a supply chain attack vector — an attacker who controls the "
                        "action repo can push malicious code to the same tag."
                    ),
                ))
        return findings
