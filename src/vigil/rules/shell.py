import re
from pathlib import Path
from .base import Finding, Rule, Severity

_SECRET_NAME = re.compile(
    r"SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PASS|PWD|CREDENTIALS?|CREDS|PRIVATE|DB_URL|DATABASE_URL",
    re.IGNORECASE,
)

# IDENTIFIER="$VAR" command  or  IDENTIFIER='$VAR' command
# Use \S (not \w) for the trailing command — catches ./script, /usr/bin/cmd, etc.
_INLINE_ENV = re.compile(r'\b(\w+)\s*=\s*["\']?\$\{?\w+\}?["\']?\s+\S')

# ssh ... IDENTIFIER="$VAR" or IDENTIFIER='$VAR' anywhere on the line
# Simple .* avoids breaking on escaped quotes inside SSH command strings
_SSH_INLINE = re.compile(r'\bssh\b.*\b(\w+)\s*=\s*\S*?\$\{?\w+\}?')


class ShellSecretInjectionRule(Rule):
    """VGL-S011 — secret variable passed inline to subprocess or SSH command.

    Fetching a secret into a shell variable is fine. Passing that variable
    inline on a command line exposes it in `ps aux` on both the local machine
    and any remote host for the duration of the process.

    Safe:   DB_URL=$(aws ssm get-parameter ...)   # assignment only
    Unsafe: DB_URL="$DB_URL" ssh host "alembic upgrade head"
    """

    id = "VGL-S011"
    name = "Secret variable passed inline to subprocess/SSH (ps aux leak)"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix in (".sh", ".bash") or path.name in ("Makefile", "GNUmakefile")

    def check(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text().splitlines()
        except OSError:
            return []

        findings: list[Finding] = []
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            # Pure assignment from subshell (SSM fetch) — fetching is fine
            if re.match(r"^\w+=\$\(", stripped):
                continue
            # export VAR or env -u VAR — not passing to subprocess
            if stripped.startswith(("export ", "env -u ")):
                continue

            # Pattern 1: SSH inline secret  (check first — more specific)
            m = _SSH_INLINE.search(stripped)
            if m and _SECRET_NAME.search(m.group(1)):
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message=(
                        f"Secret '{m.group(1)}' passed inline to SSH command — "
                        "visible in ps aux on both machines for the duration of the call"
                    ),
                    file_path=path,
                    line=i,
                    snippet=stripped[:120],
                    fix=(
                        "Have the remote script read the secret from SSM directly. "
                        "Never pass secret values via SSH command strings."
                    ),
                ))
                continue

            # Pattern 2: inline env var before any subprocess
            for m in _INLINE_ENV.finditer(stripped):
                name = m.group(1)
                if _SECRET_NAME.search(name):
                    findings.append(Finding(
                        rule_id=self.id,
                        severity=self.severity,
                        message=(
                            f"Secret '{name}' passed inline to subprocess — "
                            "visible in ps aux for the duration of the call"
                        ),
                        file_path=path,
                        line=i,
                        snippet=stripped[:120],
                        fix=(
                            "Have the called script read the secret from SSM directly. "
                            "Never pass secret values on the command line."
                        ),
                    ))
                    break

        return findings
