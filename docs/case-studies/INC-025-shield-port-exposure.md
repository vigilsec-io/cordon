# Case Study: Production Port Exposure via AI-Generated docker-compose

**Vigil rule demonstrated:** VGL-D001 — docker-compose bare port binding  
**Severity:** HIGH  
**System type:** Real-time security API (FastAPI + PostgreSQL + Redis)  
**Duration in repo:** 11 days, 9 commits  
**Active production exposure:** ~1 day  
**Detection method:** Manual code review. Zero automated tools caught it.

---

## The Vulnerability

An AI coding assistant generated `docker-compose.yml` with bare port bindings on all three services — the training-data default:

```yaml
# WHAT WAS GENERATED AND DEPLOYED
services:
  api:
    ports:
      - "8000:8000"   # application API

  db:
    ports:
      - "5432:5432"   # PostgreSQL

  redis:
    ports:
      - "6379:6379"   # Redis (no AUTH configured)
```

Docker rewrites iptables directly, bypassing UFW. The server had UFW configured with `deny-all` inbound — irrelevant. All three services were reachable on the public IP from anywhere on the internet.

```yaml
# THE FIX
services:
  api:
    ports:
      - "127.0.0.1:8000:8000"

  db:
    ports:
      - "127.0.0.1:5432:5432"

  redis:
    ports:
      - "127.0.0.1:6379:6379"
```

---

## The Timeline

| Day | Event | Tools run | Result |
|-----|-------|-----------|--------|
| Day 0 | Vulnerability introduced — AI wrote `"PORT:PORT"` (training-data default) | gitleaks, detect-secrets, bandit, check-yaml | All passed |
| Day 2 | Application endpoints added; compose touched, ports unchanged | All pre-commit hooks | All passed |
| Day 5 | **Security hardening commit** — credentials removed, CSRF added, rate limits fixed. Same file. Ports missed. | All pre-commit hooks | All passed |
| Day 5 | 4 more docker-compose fixes (unrelated). Ports still untouched. | All pre-commit hooks | All passed |
| Day 10 | Server goes live. Exposure begins. | Weekly runner: Checkov, Trivy, Semgrep, Snyk | All passed |
| Day 11 | Another security commit (request signing, audit log). Ports not caught. | All pre-commit hooks | All passed |
| Day 11 | **Fixed** — discovered manually during code review of an unrelated feature | — | — |

**9 commits. 11 days. Every automated tool returned zero findings.**

The fix came from a human noticing the pattern while looking at a completely different problem. That is not a process — that is luck.

---

## Tool-by-Tool Failure Analysis

| Tool | Used where | Why it missed VGL-D001 |
|------|-----------|----------------------|
| **gitleaks** | Pre-commit | Scans for credential string patterns — not network configuration |
| **detect-secrets** | Pre-commit | Value scanner, not structural |
| **bandit** | Pre-commit | Python AST only; never reads YAML |
| **check-yaml** | Pre-commit | Validates syntax; `"5432:5432"` is syntactically valid YAML |
| **Checkov** | CI + weekly runner | Has docker-compose rules but no rule for missing `127.0.0.1:` prefix |
| **Trivy config** | CI + weekly runner | Only scans Dockerfiles and Terraform; docker-compose not in scope |
| **Semgrep** | CI + weekly runner | YAML list-item string matching cannot reliably match the `"HOST:CONTAINER"` format |
| **Snyk** | CI + weekly runner | No rule for docker-compose port exposure |

**8 tools. Zero findings. One grep catches what all of them miss:**

```bash
grep -n '"[0-9]\+:[0-9]\+"' docker-compose.yml
```

---

## Why AI Makes This Pattern Worse

`"PORT:PORT"` appears far more often than `"127.0.0.1:PORT:PORT"` in public docker-compose examples — the majority of Docker tutorials, Stack Overflow answers, and GitHub repos use the bare form. AI coding assistants trained on this data confidently generate the insecure default every time.

This is not a one-time mistake. It is the **statistically most likely output** from any AI assistant writing a docker-compose file. Every team using AI-assisted development faces this exposure until a tool fires at generation time.

The most compelling detail from this incident: on Day 5, a developer was **explicitly focused on security**, touched the same file to fix a credentials issue, and still didn't catch the port bindings. This is not a story about negligence — it is about a tooling gap that no amount of developer attention reliably closes.

---

## What VGL-D001 Does

Vigil fires the instant the file is written — not 11 days later, not when a developer happens to notice it:

```
CRITICAL [VGL-D001] docker-compose.yml:5
  Port "8000:8000" binds to 0.0.0.0 — bypasses UFW/firewalld
  Fix: use "127.0.0.1:8000:8000" to restrict to localhost
```

The 11-day window, the 9 affected commits, and the live production exposure window would all be zero.

---

## Key Stats for Positioning

- **4 enterprise IaC tools tested on the same file. All 4 returned zero findings.**
- A dedicated security commit touched the same file and missed the exposure.
- Redis with no AUTH was readable from the public internet — session tokens, rate limit state, all accessible without credentials.
- The fix is three characters per port binding. The discovery took 11 days without Vigil.
