"""
VGL-TF001  CRITICAL  Hardcoded secret value in Terraform resource block
VGL-TF002  HIGH      Terraform resource with public access enabled
VGL-TF003  HIGH      Encryption explicitly disabled on a Terraform resource
VGL-TF004  CRITICAL  IMDSv1 enabled on EC2 instance (http_tokens = "optional")
VGL-TF005  HIGH      Terraform S3 backend state stored unencrypted (encrypt = false)
VGL-TF006  MEDIUM    Deletion protection disabled on a managed resource
VGL-TF007  MEDIUM    Audit logging disabled on a resource
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


# ── VGL-TF004 — IMDSv1 enabled ────────────────────────────────────────────────

class TerraformImdsv1Rule(Rule):
    """IMDSv1 allows SSRF to reach 169.254.169.254 without a token — a critical attack vector
    (Capital One breach 2019). IMDSv2 requires a PUT request with a TTL-bounded session token."""

    id = "VGL-TF004"
    name = "IMDSv1 enabled on EC2 instance — vulnerable to SSRF metadata theft"
    severity = Severity.CRITICAL

    _PAT = re.compile(r'http_tokens\s*=\s*"optional"', re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, [self._PAT], self.id, self.severity,
            'IMDSv1 enabled (http_tokens = "optional") — SSRF vulnerabilities can steal IAM credentials via the metadata service',
            'Set http_tokens = "required" in the metadata_options block to enforce IMDSv2. '
            "IMDSv2 requires a session-oriented PUT request that cannot be forged by typical SSRF payloads. "
            "IMDSv1 was exploited in the Capital One breach to steal IAM credentials via a misconfigured WAF.",
        )


# ── VGL-TF005 — State backend unencrypted ────────────────────────────────────

class TerraformStateEncryptionRule(Rule):
    """Terraform state files store all resource attributes in plaintext, including passwords,
    private keys, and connection strings written by providers. Unencrypted S3 state = data breach."""

    id = "VGL-TF005"
    name = "Terraform S3 state backend stored without encryption"
    severity = Severity.HIGH

    # encrypt = false  (note: distinct from `encrypted = false` caught by TF003)
    _PAT = re.compile(r"\bencrypt\s*=\s*false\b", re.IGNORECASE)

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, [self._PAT], self.id, self.severity,
            "Terraform state backend has encryption disabled — state files contain plaintext secrets from all providers",
            "Set encrypt = true in the terraform backend block. "
            "Terraform state files store every provider-managed attribute including DB passwords, private keys, and API tokens — "
            "unencrypted S3 state is equivalent to a plaintext secrets file accessible to anyone with S3 read access.",
        )


# ── VGL-TF006 — Deletion protection disabled ─────────────────────────────────

class TerraformDeletionProtectionRule(Rule):
    """deletion_protection = false on production databases allows accidental or malicious
    destroy operations to permanently delete data without a confirmation step."""

    id = "VGL-TF006"
    name = "Deletion protection disabled on managed resource"
    severity = Severity.MEDIUM

    _PATS = [
        re.compile(r'\bdeletion_protection\s*=\s*false\b', re.IGNORECASE),
        re.compile(r'\bdisable_deletion_protection\s*=\s*true\b', re.IGNORECASE),
    ]

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, self._PATS, self.id, self.severity,
            "deletion_protection = false — resource can be permanently destroyed without a protection override",
            "Set deletion_protection = true on all production databases, load balancers, and critical resources. "
            "This adds a guard that requires the protection to be explicitly disabled before a terraform destroy can succeed.",
        )


# ── VGL-TF007 — Audit logging disabled ───────────────────────────────────────

class TerraformLoggingDisabledRule(Rule):
    """Disabled audit logging means security events (failed logins, permission changes,
    data access) go unrecorded — compliance and incident response blind spot."""

    id = "VGL-TF007"
    name = "Audit logging disabled on Terraform-managed resource"
    severity = Severity.MEDIUM

    _PATS = [
        re.compile(r'\benable_logging\s*=\s*false\b', re.IGNORECASE),
        re.compile(r'\benable_cloudwatch_logs\s*=\s*false\b', re.IGNORECASE),
        re.compile(r'\benable_flow_log\s*=\s*false\b', re.IGNORECASE),
        re.compile(r'\benabled\s*=\s*false\b.*(?:log|audit)', re.IGNORECASE),
    ]

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".tf"

    def check(self, path: Path) -> list[Finding]:
        return _scan_tf(
            path, self._PATS, self.id, self.severity,
            "Audit logging disabled — security events and access patterns will not be recorded",
            "Enable logging: set enable_logging = true, enable_cloudwatch_logs = true, or configure an access_logs block. "
            "Logging is required for compliance (SOC2, PCI-DSS, HIPAA) and essential for incident response.",
        )
