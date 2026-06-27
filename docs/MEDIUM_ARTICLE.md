# I Built 12 Apps with AI. Every One Had the Same Security Hole. So I Built a Tool That Fixes It.

*The security gap no one talks about: AI coding assistants generate insecure infrastructure by default — and every existing scanner misses it.*

---

There's a vulnerability that lives in almost every project built with an AI coding assistant. It's not subtle. It's not theoretical. It's a single line in a `docker-compose.yml` that exposes your database to the entire internet — and Checkov, Trivy, Snyk, and Semgrep all give it a clean bill of health.

I found it the hard way. Then I built something about it.

---

## The Setup

Over the past year, I've been building a series of production applications with AI as my primary coding partner — backend APIs, data pipelines, mobile apps, agent systems. Twelve projects in total, spread across different tech stacks and domains.

I also ran a rigorous security setup. Every project had gitleaks and trufflehog for secret scanning, bandit and semgrep for Python SAST, trivy for container and dependency CVEs, and snyk for software composition analysis. Weekly automated scans across all twelve repos.

I thought I was covered.

Then, during a routine audit, I ran Checkov on a `docker-compose.yml`. Zero findings. Ran Trivy config scan. Zero findings. Ran Snyk. Zero findings.

The file had this in it:

```yaml
services:
  api:
    ports:
      - "8000:8000"  # FastAPI
  db:
    ports:
      - "5432:5432"  # PostgreSQL — directly exposed
  cache:
    ports:
      - "6379:6379"  # Redis — directly exposed
```

PostgreSQL and Redis, binding to `0.0.0.0`. Reachable from anywhere. On a production server.

---

## Why Every Scanner Misses It

The reason this flies under the radar is subtle but important. Docker's networking model has a non-obvious behavior: when you write `"5432:5432"` in a compose file, Docker doesn't just open that port. It rewrites `iptables` rules directly — bypassing UFW entirely. Your firewall thinks port 5432 is closed. The internet disagrees.

The correct form is `"127.0.0.1:5432:5432"` — binding to localhost only.

Checkov, Trivy, Semgrep, and Snyk all parse docker-compose files. None of them check for this pattern. I confirmed it across all four tools on the same file. Unanimous miss.

This wasn't a minor oversight in one project. I found the same pattern across the majority of my repos. The AI had generated it every time — because `"PORT:PORT"` is what dominates training data. It's the common example in every tutorial, every Stack Overflow answer, every GitHub repository the model learned from.

> **AI coding assistants reproduce the most common patterns in their training data. The most common patterns are insecure defaults.**

---

## The Insight That Changed Everything

The conventional security tooling model assumes a human wrote the code. The tools run after commit, after push, in CI — sometimes hours later.

But when an AI is generating code at 100 lines per minute, the window between "AI writes insecure infrastructure" and "that infrastructure is running in production" can be minutes, not hours. CI-gate security has a fundamentally different threat model than AI-generated security.

What you need isn't a better CI scanner. You need something that intercepts the AI *at the moment of generation* — before the file is even saved.

> That's the insight behind Vigil.

---

## How Vigil Works

Claude Code (Anthropic's AI coding CLI) exposes a `PostToolUse` hook — a shell command that runs every time the AI writes or edits a file. Vigil plugs into this hook:

```
AI writes file
     │
     ▼
plugin/hook.sh  ←── PostToolUse fires
     │
     ▼
vigil scan <file>
     │
     ├─── Engine runs all applicable rules
     │
     ├─── exit 0  →  write proceeds silently
     ├─── exit 1  →  advisory findings (MEDIUM/LOW)
     └─── exit 2  →  CRITICAL/HIGH found → Claude Code BLOCKS the write
```

Exit code 2 is the key. Claude Code reads the hook's exit code and refuses to complete the file write if it's non-zero. The insecure file never hits disk.

The engine itself is stdlib-only Python — no dependencies, no pip install surprises, no supply chain surface. It installs in five seconds and works anywhere Python 3.11+ exists.

---

## The Rule Corpus: What Vigil Catches

In two weeks of development, Vigil now has 36 rules across ten categories. Here's what makes the corpus interesting — it's not a clone of existing tools.

### Secrets & Injection

The usual suspects: hardcoded AWS keys, passwords, API tokens, JWT signing secrets, PEM private keys, credential-embedded database URLs (`postgres://user:pass@host`), Stripe live keys, Slack tokens, and provider keys (OpenAI, GitHub, GitLab, Google). Plus the injection classics: `eval()` with variable input, `subprocess(shell=True)`, `os.system()`.

These are the AI-pattern rules — not just generic secret detection, but specifically the patterns AI assistants produce when they're "helping" with authentication or system integration.

### Docker & Dockerfile

**VGL-D001** — the original discovery — catches `"PORT:PORT"` bindings. **VGL-D002** catches hardcoded secrets in `environment:` blocks, correctly ignoring safe variable references like `${DB_PASSWORD}`. On the Dockerfile side: containers running as root, unpinned `:latest` base images, and secrets baked into image layers via `ENV` or `ARG`.

### Shell Script Secret Leakage

A pattern that doesn't exist in any other scanner: deploy scripts that fetch a secret from a secrets manager into a shell variable (safe), then pass that variable inline on an SSH command string (not safe):

```bash
# This exposes DB_URL in ps aux on both machines
ssh host "DB_URL='$DB_URL' venv/bin/alembic upgrade head"
```

**VGL-S011** catches this. The fix is having the remote script read from SSM directly — no secret ever touches the command line.

### AI Agent Patterns — The New Category

This is where it gets interesting. As AI coding assistants generate more agentic code, a new class of vulnerability emerges that no existing tool covers:

- LLM output piped directly to `subprocess.run()` or `os.system()` — CRITICAL
- Hardcoded `auto_approve = True` or `skip_confirmation = True` — HIGH
- Unbounded `while True` loops that call LLMs with no iteration cap — HIGH
- LLM response content written directly to the filesystem without validation — HIGH

These are the "excessive agency" patterns. The AI is generating code that gives itself too much autonomy, and every existing scanner assumes a human is in the loop.

### Prompt Injection in AI-Calling Code

- User input embedded in system prompts — CRITICAL
- Raw `request.body` passed as LLM message content — HIGH
- `str.format()` called on `system_prompt` variables with user-controlled data — HIGH
- Unsanitized tool output appended back to the conversation — MEDIUM

### MCP Server Security

The Model Context Protocol is how AI agents extend their capabilities. Vigil catches tool poisoning via injected `description` strings, dynamic tool descriptions built from user-controlled data, and shell execution inside MCP handlers without a sandbox.

### Infrastructure & Dependencies

nginx missing security headers and deprecated TLS. Kubernetes `privileged: true` and host namespace sharing. IAM policy wildcards (`"Action": "*"`). Python CVEs via pip-audit and npm CVEs via npm audit — running immediately on every `requirements.txt` or `package.json` change, not on a weekly schedule. Trivy IaC deep scan for Dockerfile and Terraform.

---

## The Competitive Gap

I tested the docker-compose port binding issue against every major IaC scanner before writing a single line of Vigil code.

**Checkov:** ❌ misses it. **Trivy config scan:** ❌ misses it. **Semgrep:** ❌ misses it. **Snyk:** ❌ misses it.

All four tools parse docker-compose files. None catch `"PORT:PORT"`. All four run post-commit, not at generation time. None have rules for AI agent patterns, MCP security, or prompt injection in calling code.

> The docker-compose port binding miss is the beachhead story. The deeper advantage is the category: **at-generation security**. No existing tool operates at this point in the development lifecycle because the lifecycle has changed.

---

## Per-Project Configuration

Real projects have legitimate reasons to disable specific rules. That's what `.vigilrc` is for:

```toml
# .vigilrc — place in project root
disabled_rules = ["VGL-T001"]     # skip trivy scan for this project
min_severity   = "HIGH"           # only report HIGH and above
exclude_paths  = ["vendor", "legacy"]
telemetry      = false            # opt out of local telemetry
```

Vigil walks up the directory tree to find the nearest `.vigilrc`, so monorepos can have project-level overrides alongside a workspace-level default.

For a line you've reviewed and accepted:

```python
auto_approve = True  # vigil: ignore
```

Same pattern as `# noqa` (flake8) and `# nosec` (bandit). Familiar from day one.

---

## Three Output Formats

**Terminal** — colored, human-readable, fix suggestions inline:

```
CRITICAL [VGL-D001] docker-compose.yml:14
  Port "5432:5432" binds to 0.0.0.0 — bypasses UFW
  Fix: Use "127.0.0.1:5432:5432" to bind to localhost only.
```

**JSON** — machine-readable, for integrations and dashboards.

**SARIF 2.1.0** — the standard for static analysis results. GitHub Advanced Security ingests SARIF directly and annotates PRs with inline findings. The groundwork for the GitHub Actions integration is already in the output layer.

---

## Where It's Going

**Now:** Claude Code PostToolUse hook — live in my workflow, catching real issues daily.

**Next:** VS Code extension (`onDidSaveTextDocument` → `vigil scan` → inline Problem annotations). This reaches Copilot, Cursor, and Windsurf users. Same CLI, same rules, same exit codes. And a GitHub Actions integration — `vigil-action` scans changed files on every PR, posts SARIF to Advanced Security.

**Later:** Team dashboard — per-developer scan history, finding trends, which rules fire most. First paid tier.

---

---

## Try It

```bash
pip install vigilsec

# Wire the Claude Code hook (one time)
vigil init --global

# Scan a file
vigil scan docker-compose.yml

# Scan a project
vigil scan ./my-project/

# SARIF output for GitHub Advanced Security
vigil scan ./my-project/ --format sarif > results.sarif
```

The Claude Code hook takes three seconds to install. After that, every file your AI writes gets scanned before it lands on disk. The first time it blocks something you didn't catch, you'll understand why this tool exists.

---

## The Bigger Picture

Every major shift in how software is written creates a new attack surface that the tooling hasn't caught up with. The move to containers brought misconfigured Docker networking. The move to cloud brought over-permissioned IAM. The move to microservices brought insecure inter-service communication.

The move to AI-generated code is bringing something new: **patterns that are statistically common in training data but operationally dangerous in production**. The `"PORT:PORT"` pattern is the clearest example, but it's not the last. AI models optimize for code that runs, not code that runs safely.

The tooling for this shift doesn't exist yet. That's the gap. That's the product.

---

*Vigil is open-source (BUSL 1.1). Free to install, free to use, stdlib-only — no dependencies.*

*If you want early access to the VS Code extension and team features — [join the waitlist](https://thefwss.com/vigil). Takes 60 seconds. Or just run `vigil feedback`.*

---

**Tags:** `security` `devtools` `ai` `docker` `python` `developer-tools` `devsecops` `claude`

**Suggested titles:**
- *The Security Hole in Every AI-Generated docker-compose.yml*
- *I Found a Vuln That Checkov, Trivy, Snyk, and Semgrep All Miss. So I Built a Scanner.*
- *AI Coding Assistants Have a Security Problem No One Is Talking About*
