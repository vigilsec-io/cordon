"""Tests for Terraform security rules: VGL-TF001, VGL-TF002, VGL-TF003."""
import pytest
from vigil.rules.terraform import (
    TerraformHardcodedSecretRule,
    TerraformPublicAccessRule,
    TerraformEncryptionDisabledRule,
)


@pytest.fixture
def tf_file(tmp_path):
    def _make(content):
        f = tmp_path / "main.tf"
        f.write_text(content)
        return f
    return _make


# ── VGL-TF001 — Hardcoded secrets ─────────────────────────────────────────────

class TestTerraformHardcodedSecretRule:
    rule = TerraformHardcodedSecretRule()

    def test_detects_hardcoded_password(self, tf_file):
        f = tf_file('  password = "supersecretpassword123"\n')
        assert self.rule.check(f)

    def test_detects_hardcoded_api_key(self, tf_file):
        f = tf_file('  api_key = "sk-abcdef1234567890abcdef"\n')
        assert self.rule.check(f)

    def test_detects_hardcoded_secret_key(self, tf_file):
        f = tf_file('  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n')
        assert self.rule.check(f)

    def test_detects_hardcoded_token(self, tf_file):
        f = tf_file('  token = "xoxb-not-a-real-slack-token-here"\n')
        assert self.rule.check(f)

    def test_ignores_variable_reference(self, tf_file):
        f = tf_file('  password = var.db_password\n')
        assert not self.rule.check(f)

    def test_ignores_ssm_data_source(self, tf_file):
        f = tf_file('  password = data.aws_ssm_parameter.db_pass.value\n')
        assert not self.rule.check(f)

    def test_ignores_template_expression(self, tf_file):
        f = tf_file('  password = "${var.db_password}"\n')
        assert not self.rule.check(f)

    def test_ignores_empty_string(self, tf_file):
        f = tf_file('  password = ""\n')
        assert not self.rule.check(f)

    def test_ignores_comment_line(self, tf_file):
        f = tf_file('# password = "hardcoded_example"\n')
        assert not self.rule.check(f)

    def test_ignores_vigil_ignore(self, tf_file):
        f = tf_file('  password = "supersecretpassword123"  # vigil: ignore\n')
        assert not self.rule.check(f)

    def test_does_not_apply_to_non_tf(self, tmp_path):
        f = tmp_path / "main.py"
        assert not self.rule.applies_to(f)

    def test_finding_has_correct_rule_id(self, tf_file):
        f = tf_file('  password = "supersecretpassword123"\n')
        assert self.rule.check(f)[0].rule_id == "VGL-TF001"


# ── VGL-TF002 — Public access ──────────────────────────────────────────────────

class TestTerraformPublicAccessRule:
    rule = TerraformPublicAccessRule()

    def test_detects_public_read_acl(self, tf_file):
        f = tf_file('  acl = "public-read"\n')
        assert self.rule.check(f)

    def test_detects_public_read_write_acl(self, tf_file):
        f = tf_file('  acl = "public-read-write"\n')
        assert self.rule.check(f)

    def test_detects_publicly_accessible(self, tf_file):
        f = tf_file('  publicly_accessible = true\n')
        assert self.rule.check(f)

    def test_detects_open_cidr(self, tf_file):
        f = tf_file('  cidr_blocks = ["0.0.0.0/0"]\n')
        assert self.rule.check(f)

    def test_detects_open_ipv6_cidr(self, tf_file):
        f = tf_file('  ipv6_cidr_blocks = ["::/0"]\n')
        assert self.rule.check(f)

    def test_ignores_private_acl(self, tf_file):
        f = tf_file('  acl = "private"\n')
        assert not self.rule.check(f)

    def test_ignores_publicly_accessible_false(self, tf_file):
        f = tf_file('  publicly_accessible = false\n')
        assert not self.rule.check(f)

    def test_ignores_restricted_cidr(self, tf_file):
        f = tf_file('  cidr_blocks = ["10.0.0.0/8"]\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, tf_file):
        f = tf_file('# cidr_blocks = ["0.0.0.0/0"]  — do not use\n')
        assert not self.rule.check(f)

    def test_finding_is_high(self, tf_file):
        from vigil.rules.base import Severity
        f = tf_file('  publicly_accessible = true\n')
        assert self.rule.check(f)[0].severity == Severity.HIGH


# ── VGL-TF003 — Encryption disabled ──────────────────────────────────────────

class TestTerraformEncryptionDisabledRule:
    rule = TerraformEncryptionDisabledRule()

    def test_detects_storage_encrypted_false(self, tf_file):
        f = tf_file('  storage_encrypted = false\n')
        assert self.rule.check(f)

    def test_detects_encrypted_false(self, tf_file):
        f = tf_file('  encrypted = false\n')
        assert self.rule.check(f)

    def test_detects_enable_encryption_false(self, tf_file):
        f = tf_file('  enable_encryption = false\n')
        assert self.rule.check(f)

    def test_detects_empty_kms_key(self, tf_file):
        f = tf_file('  kms_key_id = ""\n')
        assert self.rule.check(f)

    def test_ignores_storage_encrypted_true(self, tf_file):
        f = tf_file('  storage_encrypted = true\n')
        assert not self.rule.check(f)

    def test_ignores_encrypted_true(self, tf_file):
        f = tf_file('  encrypted = true\n')
        assert not self.rule.check(f)

    def test_ignores_comment(self, tf_file):
        f = tf_file('# storage_encrypted = false  — do not do this\n')
        assert not self.rule.check(f)

    def test_finding_has_correct_rule_id(self, tf_file):
        f = tf_file('  storage_encrypted = false\n')
        assert self.rule.check(f)[0].rule_id == "VGL-TF003"
