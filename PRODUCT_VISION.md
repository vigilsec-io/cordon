# Vigil — Product Vision

**AI coding security co-pilot that blocks insecure code at the moment of generation, not 6 hours later in CI.**

---

## The Problem

AI coding tools (Claude Code, GitHub Copilot, Cursor, Windsurf) generate IaC and application code at high speed. They hallucinate secure-looking but insecure defaults because those defaults dominate training data:

- `"8000:8000"` in docker-compose (binds to 0.0.0.0, bypasses UFW — **no existing IaC tool catches this**)
- `FROM python:latest` (unpinned, supply-chain risk)
- Running containers as root (no USER directive)
- `shell=True` in subprocess calls
- Hardcoded secrets that "look like variables" to the AI

**Confirmed gap (2026-06-26):** shield-ecosystem had PostgreSQL, Redis, and FastAPI bound to 0.0.0.0 while Checkov, Trivy, Snyk, and Semgrep all returned 0 findings. Three live CVEs (Pillow, python-multipart, starlette) also missed by the weekly security runner. Vigil's custom rules caught all four findings in the first scan.

---

## The Solution

Vigil is a **PostToolUse hook engine**: it intercepts every file the AI writes, runs a layered security scan, and **blocks the write** if CRITICAL or HIGH findings are present. Zero lag. Zero CI wait. Zero exposure window.

```
AI writes file → Vigil scans → CRITICAL/HIGH? → Block + show fix
                              ↓
                            Clean → write proceeds silently
```

---

## Market Gap

| Tool | Docker port binding | At-generation | Dep CVE (instant) | AI-pattern rules |
|---|---|---|---|---|
| Checkov | ❌ miss | ❌ post-commit | ❌ | ❌ |
| Trivy config | ❌ miss | ❌ post-commit | ✅ (trivy fs) | ❌ |
| Semgrep | ❌ miss | ❌ post-commit | ❌ | ❌ |
| Snyk | ❌ miss | ❌ post-commit | ✅ | ❌ |
| **Vigil** | **✅ VGL-D001** | **✅ PostToolUse** | **✅ pip-audit** | **✅** |

---

## Rule Catalog (16 rules — Phase 0 + Phase 1 + Phase 2 in progress)

| Rule ID | Severity | Phase | What it catches |
|---|---|---|---|
| VGL-S001 | CRITICAL | 0 | AWS access key hardcoded (`AKIA...`) |
| VGL-S002 | CRITICAL | 0 | Hardcoded password |
| VGL-S003 | CRITICAL | 0 | Hardcoded API key |
| VGL-S004 | CRITICAL | 0 | Hardcoded token |
| VGL-I001 | CRITICAL | 0 | `eval()` / `exec()` injection |
| VGL-I002 | HIGH | 0 | `subprocess(shell=True)` |
| VGL-I003 | HIGH | 0 | `os.system()` |
| VGL-D001 | CRITICAL | 0 | **Docker `"PORT:PORT"` → 0.0.0.0 bypass** ← unique in market |
| VGL-D002 | HIGH | 2 | docker-compose `environment:` hardcoded secrets (list + mapping style) |
| VGL-DF001 | HIGH | 0 | Dockerfile running as root (no USER) |
| VGL-DF002 | MEDIUM | 0 | Unpinned `:latest` base image |
| VGL-DF003 | HIGH | 1 | `ENV PASSWORD=secret` / `ARG TOKEN=default` baked into image |
| VGL-N001 | HIGH | 1 | nginx missing X-Frame-Options / weak TLS (TLSv1.0/1.1) |
| VGL-T001 | HIGH | 1 | Trivy IaC deep scan — Dockerfile + Terraform misconfigs |
| VGL-DEP001 | HIGH | 0 | Python CVEs via pip-audit |
| VGL-DEP002 | HIGH | 0 | Critical npm CVEs via npm audit |
| VGL-K001 | CRITICAL/HIGH | 2 | K8s `privileged: true`, `hostNetwork: true`, missing `readOnlyRootFilesystem` _(next)_ |
| VGL-IAM001 | CRITICAL | 2 | IAM policy `"Action": "*"` / `"Resource": "*"` wildcards _(next)_ |

---

## Phase Roadmap

### Phase 0 — Core Engine ✅ Done (2026-06-26)
**Goal:** Working scan engine, all foundational rules, Claude Code hook, tests passing.

| Deliverable | Status |
|---|---|
| `vigil scan <file\|dir>` CLI (exit 0/1/2) | ✅ |
| 12 rules: VGL-S001–S004, VGL-I001–I003, VGL-D001, VGL-DF001–DF002, VGL-DEP001–DEP002 | ✅ |
| Terminal + JSON output formats | ✅ |
| `plugin/hook.sh` — Claude Code PostToolUse hook | ✅ |
| 31 tests, all passing | ✅ |
| CI pipeline (Gitea Actions) | ✅ |
| Zero runtime dependencies (stdlib-only) | ✅ |

**Unlocks:** Internal use — wire into this workspace as the primary scan hook.

---

### Phase 1 — Rule Expansion + Claude Code Marketplace ✅ Done (2026-06-26)
**Goal:** Expand rule coverage, publish the Claude Code plugin, first external users.

| Deliverable | Status | Notes |
|---|---|---|
| VGL-DF003: secrets in ENV/ARG layers | ✅ | `ENV PASSWORD=secret` baked into image → HIGH |
| VGL-N001: nginx security headers + weak TLS | ✅ | X-Frame-Options, server_tokens, TLSv1.1 check |
| VGL-T001: trivy IaC deep scan | ✅ | Dockerfile + Terraform; skips if trivy absent |
| SARIF output format (`--format sarif`) | ✅ | SARIF 2.1.0 — GitHub Advanced Security ready |
| `vigil init` command | ✅ | Auto-wires `.claude/settings.json`; `--global` flag |
| Claude Code plugin manifest + install docs | ✅ | `plugin/manifest.json` + `plugin/README_INSTALL.md` |
| 65 tests, all passing | ✅ | +34 tests from Phase 0 |
| LICENSE + copyright headers | ✅ | BUSL 1.1 + AUTHORS + NOTICE added |
| Publish to PyPI / Claude Code marketplace | ⏳ | After PyPI packaging pass |

**Rule count:** 16 rules (Phase 0+1 done, Phase 2 in progress)  
**Success metric:** 100 Claude Code plugin installs; first "caught a real vuln in someone else's project" report  
**Unlocks:** Free tier goes public; beachhead story is shareable.

---

### Phase 2 — VS Code Extension + Config File Support 🔄 In Progress
**Goal:** Reach Copilot/Cursor/Windsurf users; add project-level rule configuration.

| Deliverable | Status | Notes |
|---|---|---|
| `.vigilrc` config file | ✅ | Ancestor walk, `disabled_rules`, `min_severity`, `exclude_paths`; 11 tests |
| VGL-D002: compose env block secrets | ✅ | List + mapping style; variable refs skipped; HIGH; 8 tests |
| VS Code extension (`vigil-vscode`) | ⏳ | `onDidSaveTextDocument` → `vigil scan`; inline Problem annotations |
| Cursor + Windsurf support | ⏳ | Both use VS Code extension API — same extension, no rewrite |
| VGL-K001: K8s manifest security | ⏳ | `hostNetwork: true`, `privileged: true`, missing `readOnlyRootFilesystem` |
| VGL-IAM001: IAM wildcard policy | ⏳ | `"Action": "*"` or `"Resource": "*"` in policy JSON |
| Custom rule DSL | ⏳ | Users write rules in TOML — pattern + severity + fix message |
| `--watch` mode | ⏳ | `vigil scan --watch <dir>` — inotify loop for non-hook editors |

**Rule count target:** 18+ rules (targeting 22 + unlimited custom)  
**Success metric:** VS Code extension 500 installs; 1 blog post / tweet with "Vigil caught X that Checkov missed"  
**Unlocks:** Custom rule DSL is the foundation for the enterprise rule registry.

---

### Phase 3 — GitHub Actions + Team Dashboard
**Goal:** Catch AI-generated code in PRs even without the IDE plugin; first paid revenue.
**H1B gate:** Team dashboard involves Stripe and revenue — requires LLC formed + attorney sign-off.

| Deliverable | Notes |
|---|---|
| `vigil-action` GitHub Action | Runs `vigil scan` on changed files; posts SARIF to Advanced Security |
| Gitea Actions support | First-class (self-hosted Gitea is the primary VCS here) |
| Team dashboard (FastAPI + React) | Per-developer scan history, finding trends, rule hit rate |
| Stripe integration | Free → Pro upgrade flow; Team plan billing |
| API key system | Per-team key for dashboard telemetry upload (same pattern as MCP Trust Ledger) |
| SSM namespace: `/vigil/*` | `/vigil/stripe_key`, `/vigil/db_url`, `/vigil/anthropic_api_key` |
| Telegram weekly digest | Top findings across all scanned repos for the week |

**Revenue unlock:** Pro $29/mo, Team $99/mo  
**Success metric:** 1 paying team customer; dashboard showing real telemetry  
**H1B path:** Build dashboard code now (behind feature flag); wire Stripe only after LLC.

---

### Phase 4 — Enterprise + JetBrains
**Goal:** Enterprise compliance use cases; full IDE coverage.

| Deliverable | Notes |
|---|---|
| JetBrains plugin | IntelliJ Platform SDK — covers IntelliJ, PyCharm, GoLand, WebStorm |
| SOC2 evidence export | PDF report: scan coverage %, findings by severity, remediation rate |
| SIEM integration | CEF/JSON event stream to Splunk, Datadog, or generic webhook |
| Private rule registry | Enterprise-only rules hosted in the closed-source tier |
| Audit log | Per-scan log: who ran it, what file, what was found, what was done |
| SLA + support tiers | Enterprise SLA; dedicated Slack channel for paying customers |
| On-prem / air-gap install | Docker image for orgs that can't use cloud telemetry |

**Revenue unlock:** Enterprise custom pricing  
**Success metric:** 1 enterprise pilot (SOC2 compliance team); $10K ARR

---

## Distribution Strategy

### Phase 1 — Claude Code Plugin (first mover, no competition)
- PostToolUse hook on `Write|Edit` matcher
- `plugin/hook.sh` calls `vigil scan <file>` — blocks on exit code 2
- Publish to Claude Code marketplace

### Phase 2 — VS Code Extension
- `vscode.workspace.onDidSaveTextDocument` → `vigil scan`
- Works with Copilot, Cursor (uses VS Code API), Windsurf
- Largest AI coding market

### Phase 3 — GitHub Actions
- `vigil-scan` action runs on every PR
- Catches AI-generated code even when editor plugin not installed
- SARIF output → GitHub Advanced Security annotations

### Phase 4 — JetBrains Plugin
- IntelliJ Platform SDK (covers all JetBrains IDEs)

---

## Revenue Model

| Tier | Price | Target | What's included |
|---|---|---|---|
| **Free** | $0 | Individual devs | Secrets + injection checks (VGL-S/I rules) |
| **Pro** | $29/mo | Solo founders, freelancers | All rules + dep CVE scanning + blocking mode |
| **Team** | $99/mo | Startup teams | Team dashboard, per-dev scan reports, custom rules, Slack alerts |
| **Enterprise** | Custom | Companies with compliance needs | SOC2 evidence export, SIEM integration, private rule registry, SLA |

---

## Defensible Moat

1. **Timing** — only tool that blocks at generation time. Competitors block at commit/CI.
2. **VGL-D001** — confirmed unique rule. No other tool catches docker-compose port binding. This is the beachhead story: "tool missed by Checkov + Trivy + Snyk + Semgrep, caught by Vigil."
3. **AI-pattern corpus** — grows with every block fired across all customers. Competitors analyzing human-authored code miss AI-specific insecure patterns. Our corpus trains itself.
4. **Zero-dep core** — stdlib-only Python. Install in 5 seconds. Works anywhere Python 3.11+ exists.

---

## H1B-Safe Path to Market

- Open-source the scan engine (rule corpus + CLI + Claude Code hook)
- Closed-source: hosted telemetry dashboard + enterprise rule registry
- No revenue event until LLC formed — open-source product builds corpus, brand, and community
- First paid feature: Team dashboard (Stripe → SSM pattern, already built in other FWSS projects)

---

## Competitive Landscape

| Category | Tools | Vigil advantage |
|---|---|---|
| SAST | Semgrep, CodeQL, Bandit | We run at write-time, not post-commit; we catch IaC patterns they don't |
| IaC scanning | Checkov, Trivy, KICS | We catch docker-compose port binding they miss; we're IDE-native |
| Secret scanning | Gitleaks, Trufflehog, GitGuardian | They scan git history; we block before the secret is ever committed |
| Dep scanning | Snyk, Dependabot, pip-audit | We run immediately on every requirements.txt touch; they run on schedule |
| AI coding guardrails | No existing product | We are the category |

---

## Success Metrics

- **Phase 1:** 100 Claude Code plugin installs; first "caught a real vuln" testimonial
- **Phase 2:** VS Code extension 500 installs; 1 team customer
- **Phase 3:** 1 enterprise pilot (SOC2 compliance use case)
- **Corpus target:** 1,000 blocked writes = statistical dataset of AI-generated insecure patterns
