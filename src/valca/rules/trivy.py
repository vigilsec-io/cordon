import json
import subprocess
from pathlib import Path
from .base import Finding, Rule, Severity

# Maps Trivy check IDs to semantic categories so the reporter can deduplicate
# when both a native rule and Trivy catch the same root cause.
_TRIVY_CATEGORY: dict[str, str] = {
    "DS-0001": "unpinned_image",   # Image tag not pinned
    "DS-0002": "root_user",        # Container should not be run as root
    "DS-0031": "secret_in_layer",  # Secret found in ENV/ARG
    # AVD-prefixed equivalents (trivy config --format json uses both forms)
    "AVD-DS-0001": "unpinned_image",
    "AVD-DS-0002": "root_user",
    "AVD-DS-0031": "secret_in_layer",
}

_TRIVY_SEV: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "UNKNOWN": Severity.INFO,
}


class TrivyIacScanRule(Rule):
    """Runs `trivy config` on Dockerfiles and Terraform files.

    Catches misconfigurations that lightweight pattern rules miss:
    capabilities, seccomp, network policies, provider-specific checks.
    Skips silently if trivy is not installed.
    """

    id = "VGL-T001"
    name = "Trivy IaC deep scan — Dockerfile / Terraform misconfigurations"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return "Dockerfile" in path.name or path.suffix in (".tf", ".tfvars")

    def check(self, path: Path) -> list[Finding]:
        try:
            proc = subprocess.run(
                ["trivy", "config", "--format", "json", "--quiet", str(path)],
                capture_output=True,
                text=True,
                timeout=60,
            )
        except FileNotFoundError:
            return []
        except subprocess.TimeoutExpired:
            return []

        try:
            data = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return []

        findings: list[Finding] = []
        for result in data.get("Results", []):
            for misc in result.get("Misconfigurations", []):
                sev_str = misc.get("Severity", "UNKNOWN").upper()
                sev = _TRIVY_SEV.get(sev_str, Severity.INFO)
                title = misc.get("Title", "")
                rule_id = misc.get("ID", "?")
                findings.append(Finding(
                    rule_id=self.id,
                    severity=sev,
                    message=f"[{rule_id}] {title}",
                    file_path=path,
                    fix=misc.get("Resolution") or misc.get("Message") or "",
                    category=_TRIVY_CATEGORY.get(rule_id),
                ))
        return findings
