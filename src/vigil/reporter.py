import json
import sys
from pathlib import Path
from .rules import Finding, Severity

_COLORS = {
    Severity.CRITICAL: "\033[91m",
    Severity.HIGH:     "\033[93m",
    Severity.MEDIUM:   "\033[94m",
    Severity.LOW:      "\033[96m",
    Severity.INFO:     "\033[37m",
}
_RESET = "\033[0m"
_BOLD  = "\033[1m"


def _c(sev: Severity, text: str, use_color: bool) -> str:
    return f"{_COLORS[sev]}{text}{_RESET}" if use_color else text


def report_terminal(findings: list[Finding], use_color: bool = True) -> None:
    if not findings:
        return
    blocking = [f for f in findings if f.severity in (Severity.CRITICAL, Severity.HIGH)]
    advisory = [f for f in findings if f.severity not in (Severity.CRITICAL, Severity.HIGH)]

    if blocking:
        label = _c(Severity.CRITICAL, "BLOCKED", use_color)
        print(f"\n{label} — {len(blocking)} CRITICAL/HIGH finding(s):", file=sys.stderr)
        print("─" * 60, file=sys.stderr)

    for f in findings:
        loc = f"{f.file_path.name}:{f.line}" if f.line else f.file_path.name
        sev_label = _c(f.severity, f"[{f.severity.value}]", use_color)
        print(f"{sev_label} {f.rule_id} — {f.message}", file=sys.stderr)
        print(f"  at {loc}", file=sys.stderr)
        if f.snippet:
            print(f"  → {f.snippet[:120]}", file=sys.stderr)
        if f.fix:
            print(f"  fix: {f.fix}", file=sys.stderr)
        print(file=sys.stderr)

    if advisory:
        print(
            f"Advisory: {len(advisory)} MEDIUM/LOW/INFO finding(s) — not blocking.",
            file=sys.stderr,
        )


def report_json(results: dict[Path, list[Finding]]) -> str:
    out = []
    for path, findings in results.items():
        for f in findings:
            out.append({
                "rule_id": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "file": str(path),
                "line": f.line,
                "snippet": f.snippet,
                "fix": f.fix,
            })
    return json.dumps(out, indent=2)
