"""vigil scan <file|dir> [--format terminal|json|sarif] [--severity CRITICAL|HIGH|...]
vigil init [--global]
vigil feedback

Exit codes (scan):
  0 — no findings
  1 — advisory findings only (MEDIUM/LOW/INFO)
  2 — CRITICAL or HIGH findings present (causes Claude Code to block the write)
"""
import argparse
import json as _json
import sys
import webbrowser
from pathlib import Path

from .config import load_config
from .engine import Engine
from .reporter import report_terminal, report_json, report_sarif
from .rules import DEFAULT_RULES, Severity, SEVERITY_ORDER


def _find_hook_sh() -> Path | None:
    """Locate plugin/hook.sh relative to this file (works for editable installs)."""
    here = Path(__file__).resolve().parent
    candidates = [
        here.parent.parent / "plugin" / "hook.sh",    # editable: src/vigil/ → project root
        Path.home() / ".vigil" / "plugin" / "hook.sh",
        Path("/usr/local/share/vigil/hook.sh"),
    ]
    return next((p for p in candidates if p.exists()), None)


def _run_init(global_install: bool) -> None:
    hook_sh = _find_hook_sh()
    if hook_sh is None:
        print(
            "vigil init: could not locate plugin/hook.sh.\n"
            "Run from the vigil project directory or see plugin/README_INSTALL.md.",
            file=sys.stderr,
        )
        sys.exit(1)

    # Ensure hook.sh is executable — git clones and zip downloads often strip the bit
    if not hook_sh.stat().st_mode & 0o111:
        hook_sh.chmod(hook_sh.stat().st_mode | 0o755)
        print(f"Fixed execute permission on {hook_sh.name}")

    settings_path = (
        Path.home() / ".claude" / "settings.json"
        if global_install
        else Path.cwd() / ".claude" / "settings.json"
    )
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    settings: dict = {}
    if settings_path.exists():
        try:
            settings = _json.loads(settings_path.read_text())
        except (_json.JSONDecodeError, OSError):
            settings = {}

    post_tool_use: list = settings.setdefault("hooks", {}).setdefault("PostToolUse", [])
    for entry in post_tool_use:
        for h in entry.get("hooks", []):
            if Path(h.get("command", "")).name == hook_sh.name:
                print(f"Vigil hook already installed in {settings_path}")
                return

    post_tool_use.append({
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{"type": "command", "command": str(hook_sh)}],
    })
    settings_path.write_text(_json.dumps(settings, indent=2) + "\n")
    print(f"Vigil hook installed → {settings_path}")
    print("Reload Claude Code to activate.")


def _run_stats() -> None:
    from pathlib import Path as _Path
    import json as _json
    from collections import Counter

    events_file = _Path.home() / ".vigil" / "events.jsonl"

    if not events_file.exists():
        print("No scan data yet. Run vigil scan on a file to start collecting stats.")
        print("Opt-out: set VIGIL_NO_TELEMETRY=1 or telemetry=false in .vigilrc")
        return

    events: list[dict] = []
    with events_file.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(_json.loads(line))
            except _json.JSONDecodeError:
                continue

    if not events:
        print("No scan data yet.")
        return

    total = len(events)
    by_rule: Counter = Counter(e["rule_id"] for e in events)
    by_severity: Counter = Counter(e.get("severity", "?") for e in events)
    by_ext: Counter = Counter(e.get("file_ext", "") or "no ext" for e in events)
    timestamps = sorted(e["ts"] for e in events if e.get("ts"))
    first_scan = timestamps[0][:10] if timestamps else "—"
    last_scan  = timestamps[-1][:10] if timestamps else "—"

    _B = "\033[1m"
    _R = "\033[0m"
    _D = "\033[2m"
    _SEV_COLOR = {
        "CRITICAL": "\033[91m", "HIGH": "\033[93m",
        "MEDIUM": "\033[94m", "LOW": "\033[96m", "INFO": "\033[37m",
    }

    def _sev(s: str) -> str:
        return f"{_SEV_COLOR.get(s, '')}{s}{_R}"

    print(f"\n{_B}Vigil — local scan stats{_R}")
    print("─" * 44)
    print(f"  {_B}Total findings recorded{_R}   {total}")
    print(f"  {_D}First scan{_R}  {first_scan}  {_D}·  Last scan{_R}  {last_scan}")

    print(f"\n  {_B}Top rules{_R}")
    print(f"  {'─' * 42}")
    for rule_id, count in by_rule.most_common(10):
        bar = "█" * min(count, 20)
        pct = int(count / total * 100)
        print(f"  {rule_id:<12}  {bar:<20}  {count:>4}  ({pct:>2}%)")

    print(f"\n  {_B}By severity{_R}")
    print(f"  {'─' * 42}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        count = by_severity.get(sev, 0)
        if count:
            pct = int(count / total * 100)
            print(f"  {_sev(sev):<22}  {count:>4}  ({pct:>2}%)")

    print(f"\n  {_B}By file type{_R}")
    print(f"  {'─' * 42}")
    for ext, count in by_ext.most_common(8):
        print(f"  {ext:<14}  {count:>4}")

    print(f"\n{_D}Stats are local-only · stored at ~/.vigil/events.jsonl{_R}\n")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="vigil",
        description="AI coding security co-pilot — blocks insecure code at generation time.",
    )
    sub = parser.add_subparsers(dest="command")

    scan_p = sub.add_parser("scan", help="Scan a file or directory")
    scan_p.add_argument("path", type=Path)
    scan_p.add_argument(
        "--format", choices=["terminal", "json", "sarif"], default="terminal",
        help="Output format (default: terminal)",
    )
    scan_p.add_argument(
        "--severity", choices=[s.value for s in Severity], default=None,
        help="Only report findings at this severity level or higher",
    )
    scan_p.add_argument("--no-color", action="store_true", help="Disable ANSI color output")

    init_p = sub.add_parser("init", help="Wire the Vigil PostToolUse hook into .claude/settings.json")
    init_p.add_argument(
        "--global", dest="global_install", action="store_true",
        help="Install into ~/.claude/settings.json (user-wide) instead of ./.claude/settings.json",
    )

    sub.add_parser("feedback", help="Open the Vigil feedback & waitlist page")
    sub.add_parser("stats", help="Show local scan statistics from ~/.vigil/events.jsonl")

    args = parser.parse_args()
    if args.command is None:
        parser.print_help()
        sys.exit(0)

    if args.command == "feedback":
        url = "https://thefwss.com/vigil"
        print(f"Opening {url}")
        print("Or email: prem.fwss@gmail.com")
        webbrowser.open(url)
        return

    if args.command == "stats":
        _run_stats()
        return

    if args.command == "init":
        _run_init(args.global_install)
        return

    path = args.path.resolve()
    config = load_config(path)
    rules = [r for r in DEFAULT_RULES if r.id not in config.disabled_rules]
    engine = Engine(rules=rules, telemetry_enabled=config.telemetry)

    if path.is_file():
        # Honour exclude_paths for single-file scans too (same logic scan_dir uses)
        if config.exclude_paths and any(part in config.exclude_paths for part in path.parts):
            results = {}
        else:
            findings = engine.scan(path)
            results = {path: findings} if findings else {}
    elif path.is_dir():
        results = engine.scan_dir(path, extra_skip=set(config.exclude_paths))
    else:
        print(f"vigil: path not found: {path}", file=sys.stderr)
        sys.exit(1)

    all_findings = [f for fs in results.values() for f in fs]

    # --severity flag takes priority over .vigilrc min_severity
    effective_sev = args.severity or config.min_severity
    if effective_sev:
        min_order = SEVERITY_ORDER[Severity(effective_sev)]
        all_findings = [f for f in all_findings if SEVERITY_ORDER[f.severity] <= min_order]
        results = {
            p: [f for f in fs if SEVERITY_ORDER[f.severity] <= min_order]
            for p, fs in results.items()
        }
        results = {p: fs for p, fs in results.items() if fs}

    if args.format == "json":
        print(report_json(results))
    elif args.format == "sarif":
        print(report_sarif(results))
    else:
        for _path, file_findings in results.items():
            report_terminal(file_findings, use_color=not args.no_color)
        if all_findings:
            _dim = "\033[2m" if not args.no_color else ""
            _rst = "\033[0m" if not args.no_color else ""
            print(
                f"{_dim}── Vigil · feedback & waitlist → thefwss.com/vigil ──{_rst}",
                file=sys.stderr,
            )

    if engine.blocking(all_findings):
        sys.exit(2)
    if all_findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
