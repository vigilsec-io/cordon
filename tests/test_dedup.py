"""Tests for reporter deduplication: ticket #2."""
from pathlib import Path
import pytest
from vigil.reporter import dedup_findings
from vigil.rules.base import Finding, Severity


def _f(rule_id, sev, msg="msg", line=None, category=None):
    return Finding(
        rule_id=rule_id, severity=sev, message=msg,
        file_path=Path("/app/Dockerfile"),
        line=line, category=category,
    )


class TestDedupFindings:

    def test_uncategorized_pass_through_unchanged(self):
        f1 = _f("VGL-DF001", Severity.HIGH)
        f2 = _f("VGL-S001", Severity.CRITICAL)
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_two_categorized_different_categories_not_merged(self):
        f1 = _f("VGL-DF001", Severity.HIGH, category="root_user")
        f2 = _f("VGL-DF002", Severity.MEDIUM, category="unpinned_image")
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_two_categorized_same_category_merged_to_one(self):
        f1 = _f("VGL-DF001", Severity.HIGH, line=1, category="root_user")
        f2 = _f("VGL-T001", Severity.HIGH, category="root_user")
        result = dedup_findings([f1, f2])
        assert len(result) == 1

    def test_merged_keeps_higher_severity(self):
        f_high = _f("VGL-T001", Severity.CRITICAL, category="secret_in_layer")
        f_med = _f("VGL-DF003", Severity.HIGH, category="secret_in_layer")
        result = dedup_findings([f_high, f_med])
        assert result[0].severity == Severity.CRITICAL

    def test_merged_prefers_finding_with_line_number(self):
        f_with_line = _f("VGL-DF001", Severity.HIGH, line=5, category="root_user")
        f_no_line = _f("VGL-T001", Severity.HIGH, category="root_user")
        result = dedup_findings([f_no_line, f_with_line])
        assert result[0].line == 5

    def test_merged_message_includes_corroborated_by(self):
        f1 = _f("VGL-DF001", Severity.HIGH, msg="runs as root", line=1, category="root_user")
        f2 = _f("VGL-T001", Severity.HIGH, category="root_user")
        result = dedup_findings([f1, f2])
        assert "corroborated by" in result[0].message
        assert "VGL-T001" in result[0].message

    def test_merged_keeps_primary_rule_id(self):
        f_native = _f("VGL-DF001", Severity.HIGH, line=3, category="root_user")
        f_trivy = _f("VGL-T001", Severity.HIGH, category="root_user")
        result = dedup_findings([f_trivy, f_native])
        assert result[0].rule_id == "VGL-DF001"

    def test_merged_preserves_category(self):
        f1 = _f("VGL-DF001", Severity.HIGH, line=1, category="root_user")
        f2 = _f("VGL-T001", Severity.HIGH, category="root_user")
        result = dedup_findings([f1, f2])
        assert result[0].category == "root_user"

    def test_three_findings_same_category_merged_to_one(self):
        findings = [
            _f("VGL-DF001", Severity.HIGH, line=1, category="root_user"),
            _f("VGL-T001", Severity.HIGH, category="root_user"),
            _f("VGL-OTHER", Severity.MEDIUM, category="root_user"),
        ]
        result = dedup_findings(findings)
        assert len(result) == 1

    def test_different_files_same_category_not_merged(self):
        f1 = Finding(
            rule_id="VGL-DF001", severity=Severity.HIGH, message="x",
            file_path=Path("/app/Dockerfile"), line=1, category="root_user",
        )
        f2 = Finding(
            rule_id="VGL-T001", severity=Severity.HIGH, message="x",
            file_path=Path("/other/Dockerfile"), category="root_user",
        )
        result = dedup_findings([f1, f2])
        assert len(result) == 2

    def test_output_sorted_by_severity(self):
        findings = [
            _f("VGL-A", Severity.LOW, category=None),
            _f("VGL-B", Severity.CRITICAL, category=None),
            _f("VGL-C", Severity.MEDIUM, category=None),
        ]
        result = dedup_findings(findings)
        sevs = [f.severity for f in result]
        assert sevs == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]

    def test_empty_list_returns_empty(self):
        assert dedup_findings([]) == []

    def test_single_categorized_passes_through(self):
        f = _f("VGL-DF001", Severity.HIGH, category="root_user")
        result = dedup_findings([f])
        assert len(result) == 1
        assert "corroborated" not in result[0].message
