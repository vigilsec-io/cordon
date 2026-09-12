"""
VGL-RLS001  CRITICAL  PostgreSQL Row-Level Security explicitly disabled
VGL-RLS002  HIGH      Multi-tenant query missing user/tenant filter (data isolation gap)
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SQL_EXTS = {".sql"}
_CODE_EXTS = {".py", ".rb", ".js", ".ts", ".go", ".java"}
_ALL_EXTS  = _SQL_EXTS | _CODE_EXTS


# ── VGL-RLS001 — RLS explicitly disabled ──────────────────────────────────────

class RlsDisabledRule(Rule):
    id = "VGL-RLS001"
    name = "PostgreSQL Row-Level Security explicitly disabled"
    severity = Severity.CRITICAL

    _PAT = re.compile(
        r"""(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|"""
        r"""SET\s+row_security\s*=\s*(?:off|false|0)|"""
        r"""ALTER\s+TABLE\s+\S+\s+(?:NO\s+)?DISABLE\s+ROW\s+LEVEL\s+SECURITY)""",
        re.IGNORECASE,
    )
    # Also catch in Python migration files: execute("... DISABLE ROW LEVEL SECURITY ...")
    _IN_STRING = re.compile(
        r"""(?:DISABLE\s+ROW\s+LEVEL\s+SECURITY|SET\s+row_security\s*=\s*off)""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _ALL_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        findings = []
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "--", "//")):
                continue
            if "vigil: ignore" in line:
                continue
            if self._PAT.search(line) or self._IN_STRING.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="PostgreSQL Row-Level Security disabled — all rows visible to all authenticated users",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Remove DISABLE ROW LEVEL SECURITY. "
                        "Use ALTER TABLE t ENABLE ROW LEVEL SECURITY and define policies: "
                        "CREATE POLICY user_isolation ON t USING (user_id = current_user_id()). "
                        "Disabling RLS in a multi-tenant database leaks every tenant's data."
                    ),
                ))
        return findings


# ── VGL-RLS002 — Multi-tenant query without tenant filter ─────────────────────

class MissingTenantFilterRule(Rule):
    """
    Detects ORM queries in multi-tenant code that fetch objects without filtering
    by the current user or tenant — a common source of IDOR / data isolation failures.

    Heuristic: query methods (all(), filter(), get()) used after a model that
    looks multi-tenant (has 'user', 'tenant', 'org', 'account' in the name or
    surrounding context) without a corresponding filter argument.

    This is intentionally conservative: only fires when the queryset method is
    called with no arguments at all (e.g., Model.objects.all() / .get()).
    """
    id = "VGL-RLS002"
    name = "Multi-tenant ORM query missing user/tenant filter"
    severity = Severity.HIGH

    # Model.objects.all() with no filter — in files that suggest multi-tenancy
    _BARE_ALL = re.compile(
        r"""(?:objects|query)\s*\.\s*all\s*\(\s*\)""",
        re.IGNORECASE,
    )
    # .get(id=...) without user/tenant in same call
    _BARE_GET = re.compile(
        r"""\.get\s*\(\s*(?:id|pk)\s*=\s*[^,)]+\s*\)""",
        re.IGNORECASE,
    )
    # Multi-tenant signal words that make the surrounding context risky
    _MT_CONTEXT = re.compile(
        r"""\b(?:tenant|organization|org_id|account_id|workspace|company)\b""",
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _CODE_EXTS

    def check(self, path: Path) -> list[Finding]:
        try:
            content = path.read_text(errors="ignore")
        except (OSError, PermissionError):
            return []

        # Only scan files that have multi-tenant context signals
        if not self._MT_CONTEXT.search(content):
            return []

        findings = []
        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            if stripped.startswith(("#", "//")):
                continue
            if "vigil: ignore" in line:
                continue

            # .all() with no filter is almost always wrong in multi-tenant code
            if self._BARE_ALL.search(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="ORM .all() in multi-tenant context — returns every tenant's records",
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=(
                        "Add a tenant filter: Model.objects.filter(tenant=request.tenant) "
                        "or use a base queryset in get_queryset() that always scopes by tenant. "
                        "Unfiltered .all() in multi-tenant code is a direct IDOR vulnerability."
                    ),
                ))
            # .get(id=x) without user/tenant is an IDOR risk
            elif self._BARE_GET.search(line):
                # Check that neither user nor tenant appears in the same get() call
                if not re.search(r"""\.get\s*\([^)]*(?:user|tenant|org|account)[^)]*\)""", line, re.IGNORECASE):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message="ORM .get(id=...) without user/tenant scope — IDOR: any user can fetch any record",
                        file_path=path,
                        line=i,
                        snippet=line.strip()[:120],
                        fix=(
                            "Add ownership check: Model.objects.get(id=pk, user=request.user). "
                            "Fetching by ID alone lets any authenticated user access any record "
                            "by guessing or enumerating IDs (Insecure Direct Object Reference)."
                        ),
                    ))
        return findings
