"""Documentation must match the shipped engine.

These tests exist because the published listings advertised 36 rules while the
engine shipped 102 — a 66-rule understatement that sat on PyPI and the VS Code
Marketplace because the catalogue was maintained by hand.

Anything a user reads before installing is checked here: the rule count, the
rule catalogue, and the CLI command list. A release that documents something
the engine does not do — or omits something it does — fails CI.
"""

from __future__ import annotations

import re
from pathlib import Path

from vigil.rules import DEFAULT_RULES

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
VSCODE_README = REPO / "vigil-vscode" / "README.md"

# Rule IDs emitted by a parent rule class rather than registered separately.
# Keep in sync with the class that raises them; the test below proves they are real.
SUB_RULE_IDS = {"VGL-PKG002", "VGL-PKG003", "VGL-PKG004"}

# Commands intentionally omitted from the README (none today).
UNDOCUMENTED_COMMANDS: set[str] = set()


def engine_rule_ids() -> set[str]:
    """Every rule ID a user can actually see in output."""
    return {r.id for r in DEFAULT_RULES} | SUB_RULE_IDS


def documented_rule_ids() -> set[str]:
    return set(re.findall(r"\|\s*(VGL-[A-Z]+\d+)\s*\|", README.read_text()))


def test_sub_rule_ids_are_real() -> None:
    """SUB_RULE_IDS must appear in the source, or this file is lying to the others."""
    source = "\n".join(p.read_text() for p in (REPO / "src" / "vigil" / "rules").glob("*.py"))
    for rule_id in SUB_RULE_IDS:
        assert rule_id in source, f"{rule_id} is declared a sub-rule but appears nowhere in the source"


def test_readme_rule_count_matches_engine() -> None:
    """The headline number is the first thing a prospective user reads."""
    match = re.search(r"\*\*(\d+) rules across (\d+) categories\.?\*\*", README.read_text())
    assert match, "README must state '**N rules across M categories**'"
    documented_total = int(match.group(1))
    assert documented_total == len(engine_rule_ids()), (
        f"README advertises {documented_total} rules, engine emits {len(engine_rule_ids())}. "
        "Regenerate the catalogue before releasing."
    )


def test_every_engine_rule_is_documented() -> None:
    missing = sorted(engine_rule_ids() - documented_rule_ids())
    assert not missing, f"Rules shipped but undocumented: {missing}"


def test_no_documented_rule_is_missing_from_engine() -> None:
    """Documenting a rule that does not exist is worse than omitting one."""
    undocumented_in_engine = sorted(documented_rule_ids() - engine_rule_ids())
    assert not undocumented_in_engine, (
        f"README documents rules the engine does not emit: {undocumented_in_engine}"
    )


def test_every_cli_command_is_documented() -> None:
    from vigil import cli

    commands = set(getattr(cli, "COMMANDS", ())) or _commands_from_parser()
    undocumented = sorted(
        c for c in commands - UNDOCUMENTED_COMMANDS if not _mentions_command(README.read_text(), c)
    )
    assert not undocumented, f"CLI commands missing from README: {undocumented}"


def test_vscode_listing_rule_count_matches_engine() -> None:
    """The Marketplace listing is a separate public surface and drifts independently."""
    if not VSCODE_README.exists():
        return
    match = re.search(r"What It Catches \((\d+) rules?\)", VSCODE_README.read_text())
    assert match, "VS Code README must state 'What It Catches (N rules)'"
    assert int(match.group(1)) == len(engine_rule_ids()), (
        f"VS Code listing advertises {match.group(1)} rules, engine emits {len(engine_rule_ids())}"
    )


def _commands_from_parser() -> set[str]:
    """Read subcommands straight out of the argparse parser."""
    import contextlib
    import io

    from vigil import cli

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        import sys

        original, sys.argv = sys.argv, ["valca", "--help"]
        try:
            cli.main()
        finally:
            sys.argv = original
    match = re.search(r"\{([a-z,]+)\}", buf.getvalue())
    assert match, "could not read subcommands from the CLI parser"
    return set(match.group(1).split(","))


def _mentions_command(text: str, command: str) -> bool:
    return bool(re.search(rf"\b(valca|vigil)\s+{re.escape(command)}\b", text))
