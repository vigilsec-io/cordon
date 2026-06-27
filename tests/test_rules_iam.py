import pytest
from vigil.rules.iam import IamWildcardRule
from vigil.rules.base import Severity

rule = IamWildcardRule()

_IAM_ACTION_STAR = """\
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
"""

_IAM_RESOURCE_STAR = """\
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "*"
    }
  ]
}
"""

_IAM_ACTION_LIST_STAR = """\
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["*"],
      "Resource": "arn:aws:s3:::my-bucket"
    }
  ]
}
"""

_IAM_CLEAN = """\
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}
"""

_IAM_YAML_ACTION_STAR = """\
Statement:
  - Effect: Allow
    Action: "*"
    Resource: arn:aws:s3:::my-bucket/*
"""

_NOT_IAM = """\
{
  "name": "my-app",
  "version": "1.0.0"
}
"""


def test_action_star_flagged_critical(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_ACTION_STAR)
    findings = rule.check(f)
    assert any(fi.severity == Severity.CRITICAL for fi in findings)
    assert any("Action" in fi.message for fi in findings)


def test_resource_star_flagged_high(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_RESOURCE_STAR)
    findings = rule.check(f)
    assert any(fi.severity == Severity.HIGH for fi in findings)
    assert any("Resource" in fi.message for fi in findings)


def test_action_list_star_flagged(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_ACTION_LIST_STAR)
    findings = rule.check(f)
    assert any("Action" in fi.message for fi in findings)


def test_clean_policy_no_findings(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_CLEAN)
    findings = rule.check(f)
    assert findings == []


def test_yaml_iam_action_star_flagged(tmp_path):
    f = tmp_path / "iam-policy.yml"
    f.write_text(_IAM_YAML_ACTION_STAR)
    findings = rule.check(f)
    assert any("Action" in fi.message for fi in findings)


def test_finding_has_line_number(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_ACTION_STAR)
    findings = rule.check(f)
    assert all(fi.line is not None and fi.line > 0 for fi in findings)


def test_applies_to_policy_json(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text(_IAM_ACTION_STAR)
    assert rule.applies_to(f) is True


def test_applies_to_iam_yaml(tmp_path):
    f = tmp_path / "iam-policy.yml"
    f.write_text(_IAM_YAML_ACTION_STAR)
    assert rule.applies_to(f) is True


def test_does_not_apply_to_package_json(tmp_path):
    f = tmp_path / "package.json"
    f.write_text(_NOT_IAM)
    assert rule.applies_to(f) is False
