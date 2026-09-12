"""Machine-readable output must match what the documentation promises.

These formats are consumed by other tools — CI dashboards read the JSON, and
GitHub code scanning reads the SARIF and records `tool.driver` against every
alert it ingests. A drift here is worse than a drift in prose, because nobody
reads it until an integration quietly misbehaves.

Written after the published SARIF was found reporting `name: vigil` and
`version: 0.1.0` while the package was called valca and shipped 0.4.0.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from valca.engine import Engine
from valca.reporter import report_json, report_sarif
from valca.rules import DEFAULT_RULES

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"

VULNERABLE_COMPOSE = 'services:\n  db:\n    image: postgres:16\n    ports:\n      - "5432:5432"\n'

# Fields the README's JSON example shows. Consumers build against these.
DOCUMENTED_JSON_FIELDS = {"rule_id", "severity", "message", "file", "line", "snippet", "fix"}


@pytest.fixture
def findings(tmp_path: Path):
    target = tmp_path / "docker-compose.yml"
    target.write_text(VULNERABLE_COMPOSE)
    result = Engine(telemetry_enabled=False).scan(target)
    assert result, "fixture produced no findings — the rule it relies on has changed"
    return {target: result}


def _package_version() -> str:
    from importlib.metadata import version

    return version("valca")


def test_documented_formats_are_all_supported() -> None:
    """Every --format value shown in the README must actually be accepted."""
    documented = set(re.findall(r"--format (\w+)", README.read_text()))
    from valca import cli

    help_text = _cli_help(cli, ["valca", "scan", "--help"])
    match = re.search(r"--format \{([a-z,]+)\}", help_text)
    assert match, "could not read --format choices from `scan --help`"
    supported = set(match.group(1).split(","))
    # `log` and `stats` accept a narrower set; scan's is the superset.
    unsupported = sorted(f for f in documented if f not in supported)
    assert not unsupported, f"README documents --format values the CLI rejects: {unsupported}"


def test_json_output_parses_and_matches_documented_shape(findings) -> None:
    payload = json.loads(report_json(findings))
    assert isinstance(payload, list), "JSON output must be a list of findings"
    assert payload, "expected at least one finding"
    missing = DOCUMENTED_JSON_FIELDS - set(payload[0])
    assert not missing, f"JSON findings are missing documented fields: {sorted(missing)}"


def test_sarif_is_valid_2_1_0(findings) -> None:
    doc = json.loads(report_sarif(findings))
    assert doc["version"] == "2.1.0"
    assert doc["runs"], "SARIF must contain at least one run"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"], "tool.driver.name is required"
    assert doc["runs"][0]["results"], "expected at least one result"


def test_sarif_identifies_the_tool_correctly(findings) -> None:
    """GitHub code scanning records this against every alert it ingests."""
    driver = json.loads(report_sarif(findings))["runs"][0]["tool"]["driver"]
    assert driver["name"] == "valca", f"SARIF reports the tool as {driver['name']!r}"
    assert driver["version"] == _package_version(), (
        f"SARIF reports version {driver['version']!r} but the package is "
        f"{_package_version()!r} — alerts would be attributed to the wrong release"
    )


def test_sarif_rule_ids_exist_in_the_engine(findings) -> None:
    doc = json.loads(report_sarif(findings))
    reported = {r["ruleId"] for r in doc["runs"][0]["results"] if "ruleId" in r}
    known = {r.id for r in DEFAULT_RULES} | {"VGL-PKG002", "VGL-PKG003", "VGL-PKG004"}
    unknown = sorted(reported - known)
    assert not unknown, f"SARIF reports rule IDs the engine does not define: {unknown}"


def _cli_help(cli, argv: list[str] | None = None) -> str:
    import contextlib
    import io
    import sys

    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.suppress(SystemExit):
        original, sys.argv = sys.argv, (argv or ["valca", "--help"])
        try:
            cli.main()
        finally:
            sys.argv = original
    return buf.getvalue()
