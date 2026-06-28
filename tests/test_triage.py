"""Tests for vigil triage — false positive auto-resolution."""
import re
import textwrap
from pathlib import Path

import pytest

from vigil.triage import run_triage, _match_fp, _SECTION


# ── Unit tests for _match_fp ─────────────────────────────────────────────────

@pytest.mark.parametrize("desc,expect_fp,expect_fragment", [
    # Plaid sandbox
    ("[CRITICAL] password: pass_good in client.py", True, "Plaid"),
    ("[CRITICAL] username: user_good in client.py", True, "Plaid"),
    # Template DB URLs
    ("Postgres: postgresql://user:pass@host:5432", True, "Template DB URL"),
    ("Postgres: postgresql://user:password@localhost/db", True, "Template DB URL"),
    ("Postgres: postgresql://scott:tiger@127.0.0.1/mydb", True, "Template DB URL"),
    # Proxy template URLs
    ("URI: https://username:password@proxy.com", True, "Proxy template URL"),
    ("URI: http://user:pass@192.168.1.1:8080", True, "Proxy template URL"),
    # GeoJSON type names
    ("Polygon: GeofenceGeometryMultiPolygonList", True, "GeoJSON type"),
    ("Polygon: GeofenceGeometryPolygon", True, "GeoJSON type"),
    # SQLAlchemy RECORD hash
    ("Alchemy: AuKGH9c4SgfiOEJUt5vjkzSEzzscMHkM", True, "SQLAlchemy"),
    # Xcode gestalt API
    ("Box: gestaltMacOSCompatibilityBoxless", True, "Xcode system API"),
    # urllib3 test fixture — matched by Proxy template URL pattern
    ("URI: https://username:password@host.com:80/path", True, "Proxy template URL"),
    # alembic template — matched by Template DB URL pattern
    ("Postgres: postgresql://user:pass@host/mydb", True, "Template DB URL"),
    # Real findings — must NOT match
    ("Anthropic: sk-ant-api03-[REDACTED]", False, ""),
    ("AWS: AKIA[REDACTED]", False, ""),
    ("GitHub: ghp_[REDACTED]", False, ""),
    ("hardcoded SECRET_KEY = 'abc123xyz'", False, ""),
])
def test_match_fp(desc, expect_fp, expect_fragment):
    is_fp, reason = _match_fp(desc)
    assert is_fp == expect_fp, f"Expected is_fp={expect_fp} for: {desc!r}, got reason={reason!r}"
    if expect_fp and expect_fragment:
        assert expect_fragment.lower() in reason.lower(), \
            f"Expected reason containing {expect_fragment!r}, got {reason!r}"


# ── Integration tests for run_triage ─────────────────────────────────────────

_WI_TEMPLATE = textwrap.dedent("""\
    # Workspace Improvement Tasks

    ## 🤖 Agent Findings (Auto-logged)
    {items}

    ## Other Section
    - some other content
""")


def _make_wi(tmp_path: Path, items: list[str]) -> Path:
    content = _WI_TEMPLATE.format(
        items="\n".join(f"- [ ] **[proj]** {i}" for i in items)
    )
    p = tmp_path / "WORKSPACE_IMPROVEMENTS.md"
    p.write_text(content)
    return p


def test_triage_resolves_known_fps(tmp_path):
    fp_items = [
        "Postgres: postgresql://user:pass@host:5432",
        "Polygon: GeofenceGeometryMultiPolygonList",
        "URI: https://username:password@proxy.com",
    ]
    wi = _make_wi(tmp_path, fp_items)
    rc = run_triage(wi)
    assert rc == 0
    result = wi.read_text()
    # All three should be marked [x]
    assert result.count("- [x]") == 3
    assert result.count("- [ ]") == 0
    assert "AUTO-RESOLVED" in result
    assert "FALSE POSITIVE" in result


def test_triage_leaves_real_findings_open(tmp_path):
    real_items = [
        "Anthropic: sk-ant-api03-[REDACTED] in .env",
        "AWS key: AKIA[REDACTED]",
    ]
    wi = _make_wi(tmp_path, real_items)
    rc = run_triage(wi)
    assert rc == 0
    result = wi.read_text()
    assert result.count("- [ ]") == 2
    assert "- [x]" not in result


def test_triage_mixed_findings(tmp_path):
    items = [
        "Postgres: postgresql://user:pass@host:5432",   # FP
        "Anthropic: sk-ant-api03-[REDACTED] in .env",  # real
        "Polygon: GeofenceGeometryMultiPolygonList",    # FP
    ]
    wi = _make_wi(tmp_path, items)
    rc = run_triage(wi)
    assert rc == 0
    result = wi.read_text()
    assert result.count("- [x]") == 2
    assert result.count("- [ ]") == 1


def test_triage_dry_run_makes_no_changes(tmp_path):
    items = ["Postgres: postgresql://user:pass@host:5432"]
    wi = _make_wi(tmp_path, items)
    original = wi.read_text()
    rc = run_triage(wi, dry_run=True)
    assert rc == 0
    assert wi.read_text() == original  # file unchanged


def test_triage_no_section_returns_zero(tmp_path):
    p = tmp_path / "WORKSPACE_IMPROVEMENTS.md"
    p.write_text("# No agent section here\n\nJust normal content.\n")
    rc = run_triage(p)
    assert rc == 0


def test_triage_missing_file_returns_error(tmp_path):
    rc = run_triage(tmp_path / "nonexistent.md")
    assert rc == 1


def test_triage_empty_section(tmp_path):
    wi = _make_wi(tmp_path, [])  # no items in section
    rc = run_triage(wi)
    assert rc == 0


def test_triage_preserves_other_sections(tmp_path):
    items = ["Postgres: postgresql://user:pass@host:5432"]
    wi = _make_wi(tmp_path, items)
    rc = run_triage(wi)
    assert rc == 0
    result = wi.read_text()
    assert "## Other Section" in result
    assert "some other content" in result


def test_triage_adds_date_to_resolved(tmp_path):
    items = ["Postgres: postgresql://user:pass@host:5432"]
    wi = _make_wi(tmp_path, items)
    run_triage(wi)
    result = wi.read_text()
    # Should contain a date like 2026-xx-xx
    assert re.search(r'AUTO-RESOLVED \d{4}-\d{2}-\d{2}', result)
