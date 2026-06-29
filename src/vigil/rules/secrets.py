import re
from pathlib import Path
from .base import Finding, Rule, Severity

_TEXT_EXTS = {
    ".py", ".sh", ".yml", ".yaml", ".env", ".json",
    ".toml", ".cfg", ".ini", ".js", ".ts", ".rb", ".go",
}


class _GrepRule(Rule):
    """Pattern-based rule that greps a text file for a regex."""
    pattern: str
    fix: str = ""

    def applies_to(self, path: Path) -> bool:
        return path.suffix in _TEXT_EXTS or path.name.endswith(".txt")

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(errors="ignore").splitlines()
        except (OSError, PermissionError):
            return []
        rx = re.compile(self.pattern)
        return [
            Finding(
                rule_id=self.id,
                severity=self.severity,
                message=self.name,
                file_path=path,
                line=i,
                snippet=line.strip()[:120],
                fix=self.fix,
            )
            for i, line in enumerate(lines, 1)
            if rx.search(line)
            and not line.lstrip().startswith("#")
            and "vigil: ignore" not in line
            and "pragma: allowlist secret" not in line
        ]


class AwsAccessKeyRule(_GrepRule):
    id = "VGL-S001"
    name = "AWS access key hardcoded"
    severity = Severity.CRITICAL
    pattern = r"AKIA[0-9A-Z]{16}"
    fix = "Rotate this key immediately at console.aws.amazon.com/iam. Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and inject via environment variable at runtime."


class HardcodedPasswordRule(_GrepRule):
    id = "VGL-S002"
    name = "Hardcoded password"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(password|passwd|pwd)\s*=\s*["'][^"']{6,}["']"""
    fix = "Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) or inject via environment variable at runtime. Never commit credentials."


class HardcodedApiKeyRule(_GrepRule):
    id = "VGL-S003"
    name = "Hardcoded API key"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(api_key|apikey)\s*=\s*["'][^"']{10,}["']"""
    fix = "Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler). Read via os.environ at runtime — never hardcode in source."


class HardcodedTokenRule(_GrepRule):
    id = "VGL-S004"
    name = "Hardcoded bearer token"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(bot_token|access_token|refresh_token)\s*=\s*["'][^"']{20,}["']"""
    fix = "Rotate this token immediately. Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and inject via environment variable at runtime."


class EvalInjectionRule(_GrepRule):
    id = "VGL-I001"
    name = "eval() or exec() — code injection risk"
    severity = Severity.CRITICAL
    pattern = r"""(?<!\.)\b(eval|exec)\s*\("""
    fix = "Never call eval/exec on user-controlled input. Use ast.literal_eval for data, or a proper parser."


class ShellTrueRule(_GrepRule):
    id = "VGL-I002"
    name = "subprocess with shell=True"
    severity = Severity.HIGH
    # Require ( or , before shell=True — excludes natural-language descriptions in docstrings
    # e.g. "subprocess shell=True" in a docstring won't match; subprocess.run(cmd, shell=True) will
    pattern = r"""subprocess[^#\n]*[,(]\s*shell\s*=\s*True"""
    fix = "Use shell=False and pass arguments as a list: subprocess.run(['cmd', 'arg'], shell=False)"


class OsSystemRule(_GrepRule):
    id = "VGL-I003"
    name = "os.system() call"
    severity = Severity.HIGH
    pattern = r"""\bos\.system\s*\("""
    fix = "Replace with subprocess.run() — safer, captures output, raises on error."


# ── VGL-S005–S010: Extended secret patterns ────────────────────────────────────

class JwtSecretRule(_GrepRule):
    id = "VGL-S005"
    name = "Hardcoded JWT secret"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(jwt_secret|jwt_key|secret_key)\s*=\s*["'][^"']{8,}["']"""
    fix = "Rotate the signing key immediately. Move JWT secret to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and read via environment variable at runtime."


class PemPrivateKeyRule(_GrepRule):
    id = "VGL-S006"
    name = "PEM private key in source"
    severity = Severity.CRITICAL
    pattern = r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    fix = "Never commit private keys. Rotate immediately. Store in a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault) or a dedicated key store (AWS KMS, Azure Key Vault HSM)."


# Security tool config files inherently contain credential-like patterns as
# suppression regexes — do not flag them as actual embedded credentials.
_SECURITY_TOOL_CONFIGS = {
    ".trufflehog.toml", ".gitleaksignore", ".secrets.baseline",
    ".trufflehog.yml", ".trufflehog.yaml",
}


class CredentialUrlRule(_GrepRule):
    id = "VGL-S007"
    name = "Database URL with embedded credentials"
    severity = Severity.CRITICAL
    pattern = r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:@\s]+:[^@\s]+@"
    fix = "Extract credentials from the URL. Read user/password from a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault) and construct the URL at runtime."

    def applies_to(self, path: Path) -> bool:
        return super().applies_to(path) and path.name not in _SECURITY_TOOL_CONFIGS

    def check(self, path: Path) -> list[Finding]:
        if path.name in _SECURITY_TOOL_CONFIGS:
            return []
        return super().check(path)


class StripeLiveKeyRule(_GrepRule):
    id = "VGL-S008"
    name = "Stripe live secret key"
    severity = Severity.CRITICAL
    pattern = r"sk_live_[0-9a-zA-Z]{24,}"
    fix = "Rotate at dashboard.stripe.com immediately. Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and inject via environment variable."


class SlackTokenRule(_GrepRule):
    id = "VGL-S009"
    name = "Slack token hardcoded"
    severity = Severity.CRITICAL
    pattern = r"xox[bpears]-[0-9A-Za-z]{10,}-[0-9A-Za-z\-]+"
    fix = "Rotate at api.slack.com/apps immediately. Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and inject via environment variable."


class GenericProviderKeyRule(_GrepRule):
    id = "VGL-S010"
    name = "Provider API key hardcoded (OpenAI / GitHub / GitLab / Google)"
    severity = Severity.CRITICAL
    pattern = r"(?:sk-[a-zA-Z0-9]{20,}|gh[ps]_[a-zA-Z0-9]{36,}|glpat-[a-zA-Z0-9_\-]{20,}|AIza[0-9A-Za-z\-_]{35})"
    fix = "Rotate this key at the provider's console immediately. Move to a secrets manager (AWS SSM, Azure Key Vault, GCP Secret Manager, HashiCorp Vault, Doppler) and inject via environment variable."


class InsecureConfigDefaultRule(_GrepRule):
    id = "VGL-S011"
    name = "Insecure placeholder default for security-critical config"
    severity = Severity.HIGH
    # Two forms:
    # 1. os.getenv/environ.get — any string default for a secret-named var is unsafe
    # 2. custom ._get() — fires when both a secret keyword and a placeholder word appear
    pattern = (
        r"""(?i)(?:"""
        r"""os\.(?:getenv|environ\.get)\s*\(\s*["'][^"']*(?:secret|password|passwd|token|api.?key|jwt|signing)[^"']*["']\s*,\s*["'][^"']+["']"""
        r"""|"""
        r"""\._get\s*\([^)]*["'][^"']*(?:secret|password|passwd|token|api.?key|jwt|signing)[^"']*["'][^)]*,\s*["'][^"']*(?:dev[-_]|change|placeholder|example|your.?secret)[^"']*["']"""
        r""")"""
    )
    fix = (
        "Remove the hardcoded default. Raise RuntimeError at startup if the secret is not configured — "
        "fail loudly rather than fall back to a known-weak value. "
        "Example: val = os.getenv('SECRET_KEY'); if not val: raise RuntimeError('SECRET_KEY is required')"
    )
