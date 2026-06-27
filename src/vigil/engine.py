from pathlib import Path
from .rules import DEFAULT_RULES, Finding, Rule, Severity, SEVERITY_ORDER


class Engine:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self.rules = rules if rules is not None else DEFAULT_RULES

    def scan(self, path: Path) -> list[Finding]:
        """Scan a single file. Returns findings sorted by severity (CRITICAL first).

        Lines containing '# vigil: ignore' are suppressed — same pattern as
        '# noqa' (flake8) and '# nosec' (bandit).
        """
        if not path.is_file():
            return []
        try:
            source_lines = path.read_text(errors="ignore").splitlines()
        except OSError:
            source_lines = []

        applicable = [r for r in self.rules if r.applies_to(path)]
        findings: list[Finding] = []
        for rule in applicable:
            for f in rule.check(path):
                if (
                    f.line
                    and f.line <= len(source_lines)
                    and "# vigil: ignore" in source_lines[f.line - 1]
                ):
                    continue
                findings.append(f)
        return sorted(findings, key=lambda f: SEVERITY_ORDER[f.severity])

    def scan_dir(
        self,
        root: Path,
        skip: set[str] | None = None,
        extra_skip: set[str] | None = None,
    ) -> dict[Path, list[Finding]]:
        """Recursively scan all scannable files under root.

        skip: replaces the default skip set when provided.
        extra_skip: merged with the default skip set (use for .vigilrc exclude_paths).
        """
        _default = {".venv", "venv", "node_modules", ".git", "build", "dist", "__pycache__", "Pods"}
        _skip = (skip if skip is not None else _default) | (extra_skip or set())
        results: dict[Path, list[Finding]] = {}
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(s in path.parts for s in _skip):
                continue
            if not any(r.applies_to(path) for r in self.rules):
                continue
            findings = self.scan(path)
            if findings:
                results[path] = findings
        return results

    @staticmethod
    def blocking(findings: list[Finding]) -> bool:
        """True if any finding is CRITICAL or HIGH — should block the AI write."""
        return any(f.severity in (Severity.CRITICAL, Severity.HIGH) for f in findings)
