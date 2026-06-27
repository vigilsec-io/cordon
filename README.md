# Vigil

**AI coding security co-pilot — blocks insecure code at the moment of generation.**

Vigil intercepts every file an AI coding assistant writes and blocks it if CRITICAL or HIGH security findings are detected — before the file hits disk. It's the only tool that operates at generation time rather than post-commit.

```
AI writes file → vigil scan → exit 2 → Claude Code blocks the write
```

---

## The Problem

AI coding assistants reproduce the most common patterns in their training data. The most common patterns are insecure defaults.

The clearest example: every existing IaC scanner (Checkov, Trivy, Snyk, Semgrep) misses the docker-compose port binding that exposes your database to the internet:

```yaml
ports:
  - "5432:5432"   # ← binds to 0.0.0.0, bypasses UFW, reachable from anywhere
```

The correct form is `"127.0.0.1:5432:5432"`. Vigil catches it. Nothing else does.

---

## Install

```bash
pip install vigil
```

**Wire the Claude Code hook (one time):**

```bash
vigil init --global
```

That's it. Every file Claude Code writes is now scanned before it saves. Reload Claude Code to activate.

---

## Usage

```bash
# Scan a single file
vigil scan docker-compose.yml

# Scan a directory
vigil scan ./my-project/

# JSON output (for CI / dashboards)
vigil scan ./my-project/ --format json

# SARIF output (for GitHub Advanced Security)
vigil scan ./my-project/ --format sarif > results.sarif

# Only report HIGH and above
vigil scan ./my-project/ --severity HIGH

# Open feedback & waitlist form
vigil feedback
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | No findings — write proceeds |
| `1` | Advisory findings only (MEDIUM / LOW / INFO) |
| `2` | CRITICAL or HIGH found — **Claude Code blocks the write** |

---

## Rules

35 rules across 9 categories. All built-in, stdlib-only, zero runtime dependencies.

### Secrets & Injection (10 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-S001 | CRITICAL | Hardcoded AWS / cloud API keys |
| VGL-S002 | CRITICAL | Hardcoded passwords (`password =`, `passwd =`) |
| VGL-S003 | HIGH | Generic API key / token assignments |
| VGL-S004 | HIGH | Generic secret / credential assignments |
| VGL-S005 | CRITICAL | JWT signing secrets |
| VGL-S006 | CRITICAL | PEM private keys |
| VGL-S007 | CRITICAL | Credential-embedded database URLs (`postgres://user:pass@host`) |
| VGL-S008 | CRITICAL | Stripe live keys (`sk_live_...`) |
| VGL-S009 | CRITICAL | Slack tokens (`xoxb-`, `xoxp-`) |
| VGL-S010 | CRITICAL | OpenAI, GitHub, GitLab, Google provider keys |
| VGL-I001 | CRITICAL | `eval()` with variable input |
| VGL-I002 | HIGH | `subprocess(shell=True)` with variable input |
| VGL-I003 | HIGH | `os.system()` with variable input |

### Docker IaC (2 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-D001 | CRITICAL | `"PORT:PORT"` binding — bypasses UFW, exposes to internet |
| VGL-D002 | HIGH | Hardcoded secrets in `environment:` blocks |

### Dockerfile Hardening (3 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-DF001 | HIGH | Container running as root (no `USER` directive) |
| VGL-DF002 | MEDIUM | Unpinned `:latest` base image |
| VGL-DF003 | CRITICAL | Secrets baked into image layers via `ENV`/`ARG` |

### nginx (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-N001 | HIGH | Missing security headers, `server_tokens on`, deprecated TLS |

### Kubernetes (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-K001 | CRITICAL/HIGH | `privileged: true`, `hostNetwork/hostPID/hostIPC: true` |

### IAM Policies (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-IAM001 | CRITICAL/HIGH | `"Action": "*"` and `"Resource": "*"` wildcards |

### AI Agent Patterns (7 rules)

New category — catches the security anti-patterns unique to AI-generated agentic code.

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-A001 | CRITICAL | LLM output piped to `subprocess.run()` / `os.system()` |
| VGL-A002 | HIGH | Hardcoded `auto_approve = True` / `skip_confirmation = True` |
| VGL-A003 | HIGH | Unbounded `while True` loop making LLM calls with no iteration cap |
| VGL-A004 | HIGH | LLM response content written directly to filesystem |
| VGL-PI001 | CRITICAL | User input embedded in system prompt |
| VGL-PI002 | HIGH | Raw `request.body` passed as LLM message content |
| VGL-PI003 | HIGH | `str.format()` on `system_prompt` variables with user-controlled data |
| VGL-PI004 | MEDIUM | Unsanitized tool output appended to conversation |

### MCP Server Security (3 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-MCP001 | CRITICAL | Injection strings in tool descriptions (`ignore previous instructions`) |
| VGL-MCP002 | HIGH | Dynamic tool descriptions built from user-controlled data |
| VGL-MCP003 | HIGH | Shell execution inside MCP handlers without a sandbox |

### Shell Scripts (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-S011 | HIGH | Secret variable passed inline to subprocess or SSH command — visible in `ps aux` on both machines |

### Dependency CVEs (2 rules)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-DEP001 | HIGH | Python CVEs via `pip-audit` (runs on every `requirements.txt` change) |
| VGL-DEP002 | HIGH | npm CVEs via `npm audit` (runs on every `package.json` change) |

### Trivy IaC Deep Scan (1 rule)

| Rule | Severity | What it catches |
|------|----------|----------------|
| VGL-T001 | HIGH | Dockerfile and Terraform misconfigurations via Trivy |

---

## Configuration

Place a `.vigilrc` file in your project root (or any ancestor directory):

```toml
# .vigilrc
disabled_rules = ["VGL-T001"]        # skip trivy scan for this project
min_severity   = "HIGH"              # only report HIGH and above
exclude_paths  = ["vendor", "legacy"]
telemetry      = false               # opt out of anonymous local telemetry
```

Vigil walks up the directory tree to find the nearest `.vigilrc`. Child config always wins over parent. Monorepos can have per-project overrides alongside a workspace default.

**Inline suppression** — for a specific line you've reviewed and accepted:

```python
auto_approve = True  # vigil: ignore
```

Same pattern as `# noqa` (flake8) and `# nosec` (bandit).

---

## Opt-out

Vigil collects anonymous, local-only telemetry: rule ID, severity, and file extension. No file paths, no code, no identifiable data. Stored at `~/.vigil/events.jsonl` — never sent anywhere.

Opt out permanently:

```bash
export VIGIL_NO_TELEMETRY=1
```

Or in `.vigilrc`:

```toml
telemetry = false
```

---

## Adding a Rule

```python
# src/vigil/rules/my_category.py
from pathlib import Path
from .base import Finding, Rule, Severity

class MyRule(Rule):
    id = "VGL-X001"
    name = "Descriptive rule name"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".yml"

    def check(self, path: Path) -> list[Finding]:
        findings = []
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if "bad_pattern" in line:
                findings.append(Finding(
                    rule_id=self.id,
                    severity=self.severity,
                    message="Found bad pattern",
                    file_path=path,
                    line=i,
                    snippet=line.strip(),
                    fix="Do this instead.",
                ))
        return findings
```

Then add it to `DEFAULT_RULES` in `src/vigil/rules/__init__.py`. Write tests. Done.

---

## Development

```bash
git clone http://your-gitea/fwss/vigil.git
cd vigil
python3 -m venv venv && source venv/bin/activate
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

[Business Source License 1.1](LICENSE) — free for non-commercial use. Commercial use requires a license agreement. Converts to MIT on 2030-06-26.

---

## Feedback & Waitlist

Found a false positive? Want a rule that doesn't exist yet? Building with AI agents and hitting patterns Vigil should catch?

[Join the waitlist → thefwss.com/vigil](https://thefwss.com/vigil)

Or: `vigil feedback`
