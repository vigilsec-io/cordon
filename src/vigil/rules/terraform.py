"""
VGL-TF001  CRITICAL  Hardcoded secret value in Terraform resource block
VGL-TF002  HIGH      Terraform resource with public access enabled
VGL-TF003  HIGH      Encryption explicitly disabled on a Terraform resource
"""
import re
from pathlib import Path
from .base import Finding, Rule, Severity


def _scan_tf(path: Path, patterns: list, rule_id: str, severity: Severity,
             message: str, fix: str) -> list[Finding]:
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except (OSError, PermissionError):
        return []
    findings = []
    for i, line in enumerate(lines, 1):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        if "vigil: ignore" in line:
            continue
        for pat in patterns:
            if pat.search(line):
                findings.append(Finding(
                    rule_id=rule_id,
                    severity=severity,
                    message=message,
                    file_path=path,
                    line=i,
                    snippet=line.strip()[:120],
                    fix=fix,
                ))
                break  # one finding per line, first pattern wins
    return findings


# ── VGL-TF001 — Hardcoded secrets ────────────────────────────────────────────

class TerraformHardcodedSecretRule(Rule):
    id = "VGL-TF001"
    name = "Terraform hardcoded secret value"
    severity = Severity.CRITICAL

    # Matches: password = "actual_value" but NOT password = var.foo or ""
    _PAT = re.compile(
        r'''(?:password|secret(?:_key)?|api_key|access_key|private_key|token|credentials)\s*'''
        r'''=\s*"(?!\$\{)[^"]{6,}"''',
        re.IGNORECASE,
    )

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, [self._PAT], self.id, self.severity,
            "Hardcoded secret in Terraform resource — value will appear in state files",
            "Use an input variable (var.password) or fetch from a secrets manager: "
            "data.aws_ssm_parameter, data.vault_generic_secret, or var injected at plan time. "
            "Terraform state files store all values in plaintext — hardcoded secrets leak via state.",
        )


# ── VGL-TF002 — Public access ─────────────────────────────────────────────────

class TerraformPublicAccessRule(Rule):
    id = "VGL-TF002"
    name = "Terraform resource with public access enabled"
    severity = Severity.HIGH

    _PATS = [
        # S3 public ACL
        re.compile(r'acl\s*=\s*"public-(?:read|read-write)"', re.IGNORECASE),
        # RDS publicly_accessible
        re.compile(r'publicly_accessible\s*=\s*true', re.IGNORECASE),
        # Security group ingress from 0.0.0.0/0
        re.compile(r'cidr_blocks\s*=\s*\[?"?0\.0\.0\.0/0"?\]?', re.IGNORECASE),
        # IPv6 open ingress
        re.compile(r'ipv6_cidr_blocks\s*=\s*\[?"?::/0"?\]?', re.IGNORECASE),
    ]

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, self._PATS, self.id, self.severity,
            "Terraform resource exposes data or compute to the public internet",
            "Restrict access: set publicly_accessible = false, use private S3 ACLs, "
            "and scope security group ingress to specific CIDR ranges or security group IDs. "
            "Never open 0.0.0.0/0 on sensitive ports (DB, admin, internal APIs).",
        )


# ── VGL-TF003 — Encryption disabled ──────────────────────────────────────────

class TerraformEncryptionDisabledRule(Rule):
    id = "VGL-TF003"
    name = "Terraform encryption explicitly disabled"
    severity = Severity.HIGH

    _PATS = [
        re.compile(r'storage_encrypted\s*=\s*false', re.IGNORECASE),
        re.compile(r'\bencrypted\s*=\s*false', re.IGNORECASE),
        re.compile(r'enable_encryption\s*=\s*false', re.IGNORECASE),
        re.compile(r'kms_key_id\s*=\s*""', re.IGNORECASE),
    ]

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, self._PATS, self.id, self.severity,
            "Encryption explicitly disabled on a Terraform resource",
            "Enable encryption: storage_encrypted = true, encrypted = true. "
            "Provide a kms_key_id for CMK-managed encryption. "
            "Unencrypted storage violates most compliance frameworks (SOC2, PCI-DSS, HIPAA).",
        )
