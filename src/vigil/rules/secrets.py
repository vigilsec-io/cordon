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
        ]


class AwsAccessKeyRule(_GrepRule):
    id = "VGL-S001"
    name = "AWS access key hardcoded"
    severity = Severity.CRITICAL
    pattern = r"AKIA[0-9A-Z]{16}"
    fix = "Move to AWS SSM SecureString. Rotate this key immediately at AWS IAM console."


class HardcodedPasswordRule(_GrepRule):
    id = "VGL-S002"
    name = "Hardcoded password"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(password|passwd|pwd)\s*=\s*["'][^"']{6,}["']"""
    fix = "Move to SSM or environment variable injected at runtime. Never commit credentials."


class HardcodedApiKeyRule(_GrepRule):
    id = "VGL-S003"
    name = "Hardcoded API key"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(api_key|apikey)\s*=\s*["'][^"']{10,}["']"""
    fix = "Move to SSM Parameter Store. Read via os.environ or boto3 at runtime."


class HardcodedTokenRule(_GrepRule):
    id = "VGL-S004"
    name = "Hardcoded bearer token"
    severity = Severity.CRITICAL
    pattern = r"""(?i)(bot_token|access_token|refresh_token)\s*=\s*["'][^"']{20,}["']"""
    fix = "Move to SSM SecureString. Rotate the token immediately."


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
    pattern = r"""subprocess.*shell\s*=\s*True"""
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
    fix = "Move JWT secret to SSM SecureString. Rotate the signing key immediately."


class PemPrivateKeyRule(_GrepRule):
    id = "VGL-S006"
    name = "PEM private key in source"
    severity = Severity.CRITICAL
    pattern = r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
    fix = "Never commit private keys. Move to SSM SecureString or a secrets vault and rotate immediately."


class CredentialUrlRule(_GrepRule):
    id = "VGL-S007"
    name = "Database URL with embedded credentials"
    severity = Severity.CRITICAL
    pattern = r"(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis|amqp|mssql)://[^:@\s]+:[^@\s]+@"
    fix = "Extract credentials from the URL. Read user/password from SSM and construct the URL at runtime."


class StripeLiveKeyRule(_GrepRule):
    id = "VGL-S008"
    name = "Stripe live secret key"
    severity = Severity.CRITICAL
    pattern = r"sk_live_[0-9a-zA-Z]{24,}"
    fix = "Rotate at dashboard.stripe.com immediately. Move to SSM SecureString."


class SlackTokenRule(_GrepRule):
    id = "VGL-S009"
    name = "Slack token hardcoded"
    severity = Severity.CRITICAL
    pattern = r"xox[bpears]-[0-9A-Za-z]{10,}-[0-9A-Za-z\-]+"
    fix = "Rotate at api.slack.com/apps. Move to SSM SecureString."


class GenericProviderKeyRule(_GrepRule):
    id = "VGL-S010"
    name = "Provider API key hardcoded (OpenAI / GitHub / GitLab / Google)"
    severity = Severity.CRITICAL
    pattern = r"(?:sk-[a-zA-Z0-9]{20,}|gh[ps]_[a-zA-Z0-9]{36,}|glpat-[a-zA-Z0-9_\-]{20,}|AIza[0-9A-Za-z\-_]{35})"
    fix = "Rotate this key at the provider's console immediately. Move to SSM SecureString."
