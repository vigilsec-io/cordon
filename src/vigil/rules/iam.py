"""VGL-IAM001 — IAM policy wildcard Action or Resource."""
from __future__ import annotations
import json
import re
from pathlib import Path
from .base import Finding, Rule, Severity

_ACTION_STAR_JSON = re.compile(r'"Action"\s*:\s*(?:"\*"|\[.*"\*".*\])', re.DOTALL)
_RESOURCE_STAR_JSON = re.compile(r'"Resource"\s*:\s*(?:"\*"|\[.*"\*".*\])', re.DOTALL)

_APPLIES_PAT = re.compile(r"Statement", re.IGNORECASE)
_IAM_NAMES = re.compile(r"(policy|iam|trust|role|permission)", re.IGNORECASE)


def _iam_file(path: Path) -> bool:
    if _IAM_NAMES.search(path.stem):
        return True
    try:
        snippet = path.read_text(errors="replace")[:512]
    except OSError:
        return False
    return bool(_APPLIES_PAT.search(snippet))


class IamWildcardRule(Rule):
    id = "VGL-IAM001"
    severity = Severity.CRITICAL

    def applies_to(self, path: Path) -> bool:
        return path.suffix in (".json", ".yml", ".yaml") and _iam_file(path)

    def check(self, path: Path) -> list[Finding]:
        try:
            text = path.read_text(errors="replace")
        except OSError:
            return []

        findings: list[Finding] = []

        if path.suffix == ".json":
            findings.extend(self._check_text(text, path))
        else:
            findings.extend(self._check_text(text, path))

        return findings

    def _check_text(self, text: str, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        lines = text.splitlines()

        action_inline = re.compile(r'["\']?Action["\']?\s*:\s*(?:["\']?\*["\']?|\[["\']?\*["\']?\])')
        resource_inline = re.compile(r'["\']?Resource["\']?\s*:\s*(?:["\']?\*["\']?|\[["\']?\*["\']?\])')
        # Multi-line list: Action key on one line, ["*"] spanning to next line
        action_key = re.compile(r'["\']?Action["\']?\s*:\s*\[?\s*$')
        list_only_star = re.compile(r'^\s*["\']?\*["\']?\s*[,\]]\s*$')

        in_action_list = False
        action_list_start_line = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            if action_inline.search(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message='IAM "Action": "*" — grants all AWS permissions',
                    file_path=path,
                    line=i,
                    snippet=stripped,
                    fix='Restrict to specific actions: ["s3:GetObject", "s3:PutObject"]',
                ))
                in_action_list = False
            elif resource_inline.search(stripped):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.HIGH,
                    message='IAM "Resource": "*" — applies to all AWS resources',
                    file_path=path,
                    line=i,
                    snippet=stripped,
                    fix='Scope to specific ARNs: "arn:aws:s3:::my-bucket/*"',
                ))
            elif action_key.search(stripped):
                in_action_list = True
                action_list_start_line = i
            elif in_action_list and list_only_star.match(line):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=Severity.CRITICAL,
                    message='IAM "Action": "*" — grants all AWS permissions',
                    file_path=path,
                    line=action_list_start_line,
                    snippet=stripped,
                    fix='Restrict to specific actions: ["s3:GetObject", "s3:PutObject"]',
                ))
                in_action_list = False
            elif in_action_list and stripped and not stripped.startswith("#"):
                in_action_list = False

        return findings
