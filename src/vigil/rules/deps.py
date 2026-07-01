import json
import subprocess
from pathlib import Path
from .base import Finding, Rule, Severity


def _find_tool(*candidates: str) -> str | None:
    for c in candidates:
        p = Path(c)
        if p.is_file() and p.stat().st_mode & 0o111:
            return c
    return None


class PipAuditRule(Rule):
    """Calls pip-audit to check for CVEs in requirements.txt / pyproject.toml.

    pip-audit exits 1 when vulnerabilities are found (not 0).
    We capture output before checking the exit code — || true pattern.
    """

    id = "VGL-DEP001"
    name = "Vulnerable Python packages (pip-audit)"
    severity = Severity.HIGH
    _TOOLS = ("/usr/local/bin/pip-audit", "/opt/homebrew/bin/pip-audit")

    def applies_to(self, path: Path) -> bool:
        return (
            ("requirements" in path.name and path.suffix == ".txt")
            or path.name == "pyproject.toml"
        )

    def check(self, path: Path) -> list[Finding]:
        tool = _find_tool(*self._TOOLS)
        if not tool:
            return []
        try:
            result = subprocess.run(
                [tool, "-r", str(path), "--format", "json", "--no-deps"],
                capture_output=True, text=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        findings = []
        for dep in data.get("dependencies", []):
            vulns = dep.get("vulns", [])
            if not vulns:
                continue
            ids = ", ".join(v["id"] for v in vulns[:3])
            fix_versions = vulns[0].get("fix_versions") or []
            fix = fix_versions[0] if fix_versions else "no fix yet"
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f'{dep["name"]}=={dep["version"]}: {ids}',
                file_path=path,
                fix=f"Upgrade to {fix}" if fix != "no fix yet" else "No fix available — consider an alternative.",
            ))
        return findings


class NpmAuditRule(Rule):
    """Calls npm audit and reports CRITICAL severity vulnerabilities only.

    npm audit has too many HIGH findings from transitive deps; CRITICAL is the
    right threshold to avoid noise while catching real blockers.
    """

    id = "VGL-DEP002"
    name = "Critical npm vulnerability (npm audit)"
    severity = Severity.HIGH
    _TOOLS = ("/usr/local/bin/npm", "/opt/homebrew/bin/npm")

    def applies_to(self, path: Path) -> bool:
        return path.name == "package.json" and "node_modules" not in str(path)

    def check(self, path: Path) -> list[Finding]:
        if not (path.parent / "package-lock.json").exists():
            return []
        tool = _find_tool(*self._TOOLS)
        if not tool:
            return []
        try:
            result = subprocess.run(
                [tool, "audit", "--json"],
                capture_output=True, text=True, timeout=60,
                cwd=path.parent,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        findings = []
        for name, vuln in data.get("vulnerabilities", {}).items():
            if vuln.get("severity") != "critical":
                continue
            via = vuln.get("via", [])
            source = (
                via[0] if isinstance(via[0], str)
                else via[0].get("title", "?") if via
                else "?"
            )
            findings.append(Finding(
                rule_id=self.id,
                severity=self.severity,
                message=f"{name} [CRITICAL]: {source}",
                file_path=path,
                fix="Run npm audit fix or pin to a safe version in package.json.",
            ))
        return findings


class OsvScannerRule(Rule):
    """VGL-DEP003: CVEs in Go/Rust/Maven/Gradle lockfiles via osv-scanner CLI.

    osv-scanner exits 1 when vulnerabilities are found.  We capture stdout
    regardless of exit code, so fail-open if the tool is absent or times out.
    """

    id = "VGL-DEP003"
    name = "Vulnerable lockfile package (osv-scanner)"
    severity = Severity.HIGH
    _LOCKFILES = {"go.sum", "Cargo.lock", "pom.xml", "gradle.lockfile"}
    _TOOLS = (
        "/opt/homebrew/bin/osv-scanner",
        "/usr/local/bin/osv-scanner",
        "/usr/bin/osv-scanner",
    )

    def applies_to(self, path: Path) -> bool:
        return path.name in self._LOCKFILES

    def check(self, path: Path) -> list[Finding]:
        tool = _find_tool(*self._TOOLS)
        if not tool:
            return []
        try:
            result = subprocess.run(
                [tool, "scan", "--format", "json", str(path)],
                capture_output=True, text=True, timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return []
        raw = result.stdout.strip()
        if not raw:
            return []
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return []
        findings = []
        for res in data.get("results", []):
            for pkg in res.get("packages", []):
                vulns = pkg.get("vulnerabilities", [])
                if not vulns:
                    continue
                info = pkg.get("package", {})
                pkg_name = info.get("name", "unknown")
                version = info.get("version", "?")
                ids = ", ".join(v["id"] for v in vulns[:3])
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=f"{pkg_name}@{version}: {ids}",
                    file_path=path,
                    fix=f"Upgrade {pkg_name} to a patched version. See https://osv.dev/ for details.",
                ))
        return findings
