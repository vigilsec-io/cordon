"""
vigil triage — auto-resolve known false positives in WORKSPACE_IMPROVEMENTS.md.

Each entry in _KNOWN_FP_PATTERNS is (regex, human reason). When a finding's
description matches a pattern the item is marked [x] inline and counted as
auto-resolved. Genuine findings with no match are left as [ ] for human review.
"""
import re
import sys
from datetime import datetime, UTC
from pathlib import Path


# ── False positive registry ──────────────────────────────────────────────────
# Mirror of shared/agents/findings.py _KNOWN_FP_PATTERNS — kept in sync manually.
# vigil is stdlib-only so it cannot import from the shared agents package.
_KNOWN_FP_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'pass_good|user_good', re.I),
     "Plaid sandbox test credential"),
    (re.compile(
        r'postgresql?://(?:user|username|scott|admin):(?:pass|password|tiger|secret)@(?:host|localhost|127)',
        re.I),
     "Template DB URL in library docs"),
    (re.compile(
        r'https?://(?:username|user|samuel|jo%40email\.com):(?:password|pass|a%20secret)@',
        re.I),
     "Proxy template URL in library docs"),
    (re.compile(r'GeofenceGeometry', re.I),
     "GeoJSON type name, not a secret"),
    (re.compile(r'^Alchemy:\s+[A-Za-z0-9+/]{20,}$'),
     "SQLAlchemy RECORD file hash"),
    (re.compile(r'gestaltMacOS', re.I),
     "Xcode system API name, not a secret"),
    (re.compile(r'ios/Pods.*Box:|Box:.*ios/Pods', re.I),
     "CocoaPods CodeResources build hash"),
    # urllib3 / httpx URL-parsing test fixtures
    (re.compile(r'username:password@host\.com', re.I),
     "urllib3 URL-parsing test fixture"),
    # alembic venv source template string
    (re.compile(r'user:pass@host', re.I),
     "Alembic example DB URL template"),
]

_SECTION = "## 🤖 Agent Findings (Auto-logged)"
_OPEN_RE = re.compile(r'^(\s*- )\[ \] (.+)$')


def _match_fp(desc: str) -> tuple[bool, str]:
    for pattern, reason in _KNOWN_FP_PATTERNS:
        if pattern.search(desc):
            return True, reason
    return False, ""


def _find_workspace_improvements(start: Path) -> Path | None:
    """Walk up from start looking for WORKSPACE_IMPROVEMENTS.md."""
    for candidate in [start, *start.parents]:
        p = candidate / "WORKSPACE_IMPROVEMENTS.md"
        if p.exists():
            return p
    return None


def run_triage(workspace_improvements: Path | None, dry_run: bool = False) -> int:
    """
    Triage open findings in WORKSPACE_IMPROVEMENTS.md.
    Returns exit code: 0 = ok, 1 = error.
    """
    if workspace_improvements is None:
        workspace_improvements = _find_workspace_improvements(Path.cwd())
    if workspace_improvements is None or not workspace_improvements.exists():
        print("ERROR: could not find WORKSPACE_IMPROVEMENTS.md — pass --workspace <path>",
              file=sys.stderr)
        return 1

    text = workspace_improvements.read_text()
    if _SECTION not in text:
        print(f"No '{_SECTION}' section found — nothing to triage.")
        return 0

    date_str = datetime.now(UTC).strftime("%Y-%m-%d")
    lines = text.splitlines(keepends=True)

    in_section = False
    resolved: list[tuple[str, str]] = []   # (original desc, reason)
    skipped: list[str] = []                 # open items that need human review
    out_lines: list[str] = []

    for line in lines:
        if line.rstrip() == _SECTION:
            in_section = True
            out_lines.append(line)
            continue

        if in_section and line.startswith("## ") and line.rstrip() != _SECTION:
            in_section = False

        if in_section:
            m = _OPEN_RE.match(line.rstrip("\n"))
            if m:
                prefix, desc = m.group(1), m.group(2)
                is_fp, reason = _match_fp(desc)
                if is_fp:
                    resolved.append((desc, reason))
                    if not dry_run:
                        out_lines.append(
                            f"{prefix}[x] {desc}"
                            f" — AUTO-RESOLVED {date_str}: FALSE POSITIVE ({reason})\n"
                        )
                    else:
                        out_lines.append(line if line.endswith("\n") else line + "\n")
                    continue
                else:
                    skipped.append(desc)

        out_lines.append(line if line.endswith("\n") else line + "\n")

    # ── Report ───────────────────────────────────────────────────────────────
    total = len(resolved) + len(skipped)
    if total == 0:
        print("No open [ ] findings in the Agent Findings section.")
        return 0

    print(f"\n{'DRY RUN — ' if dry_run else ''}Triaged {total} open finding(s):\n")

    if resolved:
        print(f"  ✅ Auto-resolved {len(resolved)} false positive(s):")
        for desc, reason in resolved:
            short = desc[:80] + ("…" if len(desc) > 80 else "")
            print(f"     [{reason}] {short}")

    if skipped:
        print(f"\n  ⚠️  {len(skipped)} finding(s) need manual review:")
        for desc in skipped:
            short = desc[:80] + ("…" if len(desc) > 80 else "")
            print(f"     {short}")

    print()

    if dry_run:
        print("Dry run — no changes written.")
        return 0

    workspace_improvements.write_text("".join(out_lines))
    print(f"Wrote {workspace_improvements}")
    return 0
