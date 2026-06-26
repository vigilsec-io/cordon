"""vigil scan <file|dir> [--format terminal|json] [--severity CRITICAL|HIGH|...]

Exit codes:
  0 — no findings
  1 — advisory findings only (MEDIUM/LOW/INFO)
  2 — CRITICAL or HIGH findings present (causes Claude Code to block the write)
"""
import argparse
import sys
from pathlib import Path

from .engine import Engine
from .reporter import report_terminal, report_json
from .rules import Severity, SEVERITY_ORDER


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="AI coding security co-pilot — blocks insecure code at generation time.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", type=Path)
    scan_p.add_argument(
        "--format", choices=["terminal", "json"], default="terminal",
        help="Output format (default: terminal)",
    )
    scan_p.add_argument(
        "--severity", choices=[s.value for s in Severity], default=None,
        help="Only report findings at this severity level or higher",
    )
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    engine = Engine()
    path = args.path.resolve()

    if path.is_file():
        findings = engine.scan(path)
        results = {path: findings} if findings else {}
    elif path.is_dir():
        results = engine.scan_dir(path)
    else:
        print(f"vigil: path not found: {path}", file=sys.stderr)
        sys.exit(1)

    all_findings = [f for fs in results.values() for f in fs]

    if args.severity:
        min_order = SEVERITY_ORDER[Severity(args.severity)]
        all_findings = [f for f in all_findings if SEVERITY_ORDER[f.severity] <= min_order]
        results = {
            p: [f for f in fs if SEVERITY_ORDER[f.severity] <= min_order]
            for p, fs in results.items()
        }
        results = {p: fs for p, fs in results.items() if fs}

    if args.format == "json":
        print(report_json(results))
    else:
        for _path, file_findings in results.items():
            report_terminal(file_findings, use_color=not args.no_color)

    if engine.blocking(all_findings):
        sys.exit(2)
    if all_findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
