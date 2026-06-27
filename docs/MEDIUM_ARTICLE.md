# I Built 12 Apps with AI. Every One Had the Same Security Hole. So I Built a Tool That Fixes It.

*The security gap no one talks about: AI coding assistants generate insecure infrastructure by default — and every existing scanner misses it.*

---

There's a vulnerability that lives in almost every project built with an AI coding assistant. It's not subtle. It's not theoretical. It's a single line in a `docker-compose.yml` that exposes your database to the entire internet — and Checkov, Trivy, Snyk, and Semgrep all give it a clean bill of health.

I found it the hard way. Then I built something about it.

---

## The Setup

Over the past year, I've been building a suite of products — an AI-powered scam detection app, a stock trading agent, a supplement price tracker, a voice-to-note app, a flight deal finder, and more. Twelve projects in total, all built with AI as a coding partner.

I also ran a rigorous security setup. Every project had:

- `gitleaks` and `trufflehog` for secret scanning
- `bandit` and `semgrep` for Python SAST
- `trivy` for container and dependency CVEs
- `snyk` for software composition analysis
- Weekly automated scans across all twelve repos

I thought I was covered.

Then, during a routine audit of my fraud detection API, I ran Checkov on the `docker-compose.yml`. Zero findings. Ran Trivy config scan. Zero findings. Ran Snyk. Zero findings.

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

This wasn't a minor oversight in one project. I found the same pattern in eight of my twelve repos. The AI had generated it every time, because `"PORT:PORT"` is what dominates training data. It's the common example in every tutorial, every Stack Overflow answer, every GitHub repository the model learned from.

**AI coding assistants reproduce the most common patterns in their training data. The most common patterns are insecure defaults.**

---

## The Insight That Changed Everything

The conventional security tooling model assumes a human wrote the code. The tools run after commit, after push, in CI — sometimes hours later.

But when an AI is generating code at 100 lines per minute, the window between "AI writes insecure infrastructure" and "that infrastructure is running in production" can be minutes, not hours. CI-gate security has a fundamentally different threat model than AI-generated security.

What you need isn't a better CI scanner. You need something that intercepts the AI *at the moment of generation* — before the file is even saved.

That's the insight behind Vigil.

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

In two weeks of development, Vigil now has 35 rules across nine categories:

**Secrets & Injection** (10 rules)
Hardcoded AWS keys, passwords, API tokens, JWT secrets, PEM private keys, Stripe live keys, Slack tokens, credential-embedded database URLs, and provider keys (OpenAI, GitHub, GitLab, Google). `eval()` injection. `subprocess(shell=True)`. `os.system()`. AI assistants produce these when they're "helping" with authentication — Vigil catches them before the file saves.

**Docker IaC** (2 rules)
`VGL-D001` — the original discovery — catches `"PORT:PORT"` bindings in docker-compose. `VGL-D002` catches hardcoded secrets in `environment:` blocks, correctly ignoring safe variable references (`${DB_PASSWORD}`).

**Dockerfile Hardening** (3 rules)
Container running as root. Unpinned `:latest` base image. Secrets baked into image layers via `ENV PASSWORD=secret` or credential-embedded URLs in `ARG` values.

**nginx Security** (1 rule)
Missing `X-Frame-Options`, `X-Content-Type-Options`, `server_tokens off`. Deprecated TLS versions (TLSv1.0, TLSv1.1).

**Kubernetes** (1 rule)
`privileged: true` (full host kernel access — CRITICAL). `hostNetwork`, `hostPID`, `hostIPC` (host namespace sharing — HIGH). AI-generated K8s manifests are often stripped-down demos — not production-hardened.

**IAM Policies** (1 rule)
`"Action": "*"` and `"Resource": "*"`. Wildcards appear constantly in AI-generated IAM policies because they "work" in development. Vigil catches both inline and multi-line list formats.

**AI Agent Patterns** (7 rules — the new category)
This is where it gets interesting. As AI coding assistants generate more agentic code, a new class of vulnerability emerges. Vigil catches:
- LLM output piped directly to `subprocess.run()` or `os.system()` (CRITICAL)
- Hardcoded `auto_approve = True` or `skip_confirmation = True` (HIGH)
- Unbounded `while True` loops that call LLMs with no iteration cap (HIGH)
- LLM response content written directly to the filesystem without validation (HIGH)
- User input embedded in system prompts — the classic prompt injection vector (CRITICAL)
- Raw `request.body` passed as LLM message content (HIGH)
- `str.format()` called on `system_prompt` variables with user-controlled data (HIGH)

**MCP Server Security** (3 rules)
The Model Context Protocol is how AI agents extend their capabilities. Vigil catches tool poisoning via injected `description` strings, dynamic tool descriptions built from user-controlled data, and shell execution inside MCP handlers without a sandbox.

**Dependency CVEs** (2 rules)
`pip-audit` and `npm audit` run immediately on every `requirements.txt` or `package.json` touch. Not on schedule. Not in CI. Right now.

**Trivy IaC deep scan** (1 rule)
Wraps Trivy's config scanner for Dockerfile and Terraform files.

---

## The Competitive Gap (Confirmed, Not Claimed)

I tested the docker-compose port binding issue against every major IaC scanner before writing a single line of Vigil code. The results were unambiguous:

| Tool | Docker port binding | At-generation | AI-pattern rules | Zero deps |
|------|--------------------|--------------|--------------------|-----------|
| Checkov | ❌ | ❌ post-commit | ❌ | ❌ |
| Trivy config | ❌ | ❌ post-commit | ❌ | ❌ |
| Semgrep | ❌ | ❌ post-commit | ❌ | ❌ |
| Snyk | ❌ | ❌ post-commit | ❌ | ❌ |
| **Vigil** | **✅ VGL-D001** | **✅ PostToolUse** | **✅ 35 rules** | **✅** |

The docker-compose port binding miss is the beachhead story. But the deeper advantage is the category: **at-generation security**. No existing tool operates at this point in the development lifecycle because the lifecycle has changed. AI coding assistants are new. The tooling hasn't caught up.

---

## What the Architecture Looks Like

```
src/vigil/
├── engine.py        — Engine class: scan(), scan_dir(), blocking()
├── cli.py           — vigil scan + vigil init CLI
├── config.py        — .vigilrc loader (ancestor walk, per-project overrides)
├── reporter.py      — Terminal + JSON + SARIF 2.1.0 output
└── rules/
    ├── base.py      — Severity, Finding, Rule ABC
    ├── secrets.py   — VGL-S001–S004, VGL-I001–I003
    ├── docker.py    — VGL-D001, VGL-D002
    ├── dockerfile.py — VGL-DF001, DF002, DF003
    ├── nginx.py     — VGL-N001
    ├── trivy.py     — VGL-T001
    ├── k8s.py       — VGL-K001
    ├── iam.py       — VGL-IAM001
    └── deps.py      — VGL-DEP001, VGL-DEP002

plugin/
├── hook.sh          — Claude Code PostToolUse hook
├── manifest.json    — Plugin descriptor (marketplace-ready)
└── README_INSTALL.md — 3-step install guide
```

Adding a new rule is intentionally minimal:

```python
class MyNewRule(Rule):
    id = "VGL-X001"
    severity = Severity.HIGH

    def applies_to(self, path: Path) -> bool:
        return path.suffix == ".yml"

    def check(self, path: Path) -> list[Finding]:
        findings = []
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if "some_bad_pattern" in line:
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

Add it to `DEFAULT_RULES`. Write tests. Done. No framework knowledge required.

---

## Per-Project Configuration

Real projects have legitimate reasons to disable specific rules. A Terraform project that intentionally grants broad IAM permissions (with compensating controls elsewhere) shouldn't be blocked on every save. That's what `.vigilrc` is for:

```toml
# .vigilrc — place in project root
disabled_rules = ["VGL-T001"]     # skip trivy scan for this project
min_severity   = "HIGH"           # only report HIGH and above
exclude_paths  = ["vendor", "legacy"]
```

Vigil walks up the directory tree from the scanned file to find the nearest `.vigilrc`, so monorepos can have project-level overrides alongside a workspace-level default. Child config always wins.

---

## The Output

Three formats, depending on the context:

**Terminal** (default) — colored, human-readable, fix suggestions inline:
```
CRITICAL [VGL-D001] docker-compose.yml:14
  Port "5432:5432" binds to 0.0.0.0 — bypasses UFW
  Fix: Use "127.0.0.1:5432:5432" to bind to localhost only.
```

**JSON** — machine-readable, for integrations and dashboards.

**SARIF 2.1.0** — the standard format for static analysis results. GitHub Advanced Security ingests SARIF directly and annotates PRs with inline findings. The groundwork for the GitHub Actions integration is already in the output layer.

---

## Where It's Going

**Now:** Claude Code PostToolUse hook — live in my workflow, catching real issues daily.

**Next (Phase 2 — in progress):**
- VS Code extension — `onDidSaveTextDocument` → `vigil scan` → inline `Problem` annotations. This reaches Copilot users, Cursor users, Windsurf users. Same CLI, same rules, same exit codes.
- PyPI publish — `pip install vigil`. Free. No account. No API key. Just the scanner.

**Phase 3 (H1B gated — building now, shipping later):**
- GitHub Actions integration — `vigil-action` scans changed files on every PR, posts SARIF to Advanced Security
- Team dashboard — per-developer scan history, finding trends, which rules fire most
- First paid tier: Team plan

**Phase 4:**
- JetBrains plugin (IntelliJ, PyCharm, GoLand)
- SOC2 evidence export (a security team's dream: PDF showing scan coverage %, findings by severity, remediation rate)
- Enterprise private rule registry

---

## The Honest Constraints

I'm building this on an H1B visa with an immigration petition in progress. That means no LLC, no Stripe, no revenue events until an attorney signs off. Everything in Phases 0-2 is intentionally structured to be publishable and useful without generating income. The tool is licensed under BUSL 1.1 — free for non-commercial use, commercial use requires an agreement, converts to MIT in four years.

This constraint is actually clarifying. It forces the product to earn trust on merit before it earns money. If it's genuinely useful — if it catches things that Checkov and Trivy and Snyk miss — it won't need a sales pitch.

---

## Try It

```bash
# Install
pip install vigil  # coming soon — or clone and pip install -e .

# Scan a file
vigil scan docker-compose.yml

# Scan a project
vigil scan ./my-project/

# Wire the Claude Code hook (one time)
vigil init --global

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

*Vigil is open-source (BUSL 1.1). The rule corpus, CLI, and Claude Code plugin are free. If you're building with AI coding assistants and deploying infrastructure, install it before your next session.*

*If you want early access to the VS Code extension, PyPI release, and team features — [join the waitlist](https://form.typeform.com/to/AEs5yinT). Takes 60 seconds.*

---

**Tags:** `security` `devtools` `ai` `docker` `python` `opentowork` `developer-tools` `devsecops`

**Suggested title variants:**
- *The Security Hole in Every AI-Generated docker-compose.yml*
- *I Found a Vuln That Checkov, Trivy, Snyk, and Semgrep All Miss. So I Built a Scanner.*
- *AI Coding Assistants Have a Security Problem No One Is Talking About*
