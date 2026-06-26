# Vigil — Active Task State

> **Purpose:** Read at the START of every session to resume exactly where the last session ended.
> Update whenever a task step completes or a session closes.

---

## Last Updated: 2026-06-26

**Status:** Phase 0 fully complete. 31/31 tests passing. Gitea repo live. Vigil CLI working. This terminal is dedicated to Vigil — Shield work runs in a separate terminal.

---

## Phase 0 — Completed This Session (2026-06-26)

### Code
1. ✅ **src/vigil/rules/base.py** — `Severity`, `Finding`, `Rule` ABC, `SEVERITY_ORDER`
2. ✅ **src/vigil/rules/secrets.py** — VGL-S001–S004 (key/password/api/token), VGL-I001–I003 (eval/shell/os.system)
3. ✅ **src/vigil/rules/docker.py** — VGL-D001: unique docker-compose port binding rule (confirmed gap across Checkov/Trivy/Snyk/Semgrep)
4. ✅ **src/vigil/rules/dockerfile.py** — VGL-DF001 (root user), VGL-DF002 (unpinned :latest)
5. ✅ **src/vigil/rules/deps.py** — VGL-DEP001 (pip-audit), VGL-DEP002 (npm audit)
6. ✅ **src/vigil/rules/__init__.py** — `DEFAULT_RULES` list + all exports
7. ✅ **src/vigil/engine.py** — `Engine.scan()`, `Engine.scan_dir()`, `Engine.blocking()`
8. ✅ **src/vigil/reporter.py** — colored terminal + JSON output
9. ✅ **src/vigil/cli.py** — `vigil scan <file|dir>` CLI (exit 0/1/2)
10. ✅ **plugin/hook.sh** — Claude Code PostToolUse hook (calls vigil, falls back to shared/scan.sh)
11. ✅ **31 tests** across test_engine.py (12), test_rules_docker.py (9), test_rules_secrets.py (11) — all passing
12. ✅ **pyproject.toml** — `build-backend = "setuptools.build_meta"` (not legacy); `vigil` CLI entry point
13. ✅ **.gitea/workflows/test.yml** — CI (pytest + bandit + trivy)

### Docs + Workspace
14. ✅ **PRODUCT_VISION.md** — problem, market gap table, rule catalog, 4-phase roadmap, distribution strategy, revenue model, moat, H1B path, competitive landscape, success metrics
15. ✅ **CLAUDE.md** — session protocol, project structure, rule naming convention, agent compatibility
16. ✅ **Workspace CLAUDE.md** — Vigil added to project table
17. ✅ **security_runner.py** — "vigil" added to PROJECTS list
18. ✅ **WORKSPACE_IMPROVEMENTS.md** — Sprint 0 tasks marked done; Sprint 1 tasks listed
19. ✅ **ACTIVE_WORKSPACE.md** — Vigil row added to per-project table
20. ✅ **shared/GAPS.md** — market gap logged with full evidence (confirmed no other tool catches VGL-D001)

### Infra
21. ✅ **Gitea repo** `fwss/vigil` created and pushed — http://100.80.161.44:3000/fwss/vigil
22. ✅ **venv installed** at `vigil/venv/` with Python 3.12, vigil editable install, pytest

---

## CLI Verified Working

```bash
# From vigil/ directory:
venv/bin/vigil scan tests/fixtures/docker-compose-unsafe.yml
# → BLOCKED: 3 CRITICAL findings (ports 8000, 5432, 6379 exposed)
# → exit code 2

venv/bin/vigil scan tests/fixtures/docker-compose-safe.yml
# → clean, exit code 0

venv/bin/pytest tests/ -v
# → 31 passed in 0.03s
```

---

## Next Steps — Phase 1 (start here next session)

**Resume instruction:** Start with step 1. Read PRODUCT_VISION.md Phase 1 section for full deliverable list.

1. **Add VGL-T001** — trivy IaC deep-scan rule (`src/vigil/rules/trivy.py`)
   - Calls `trivy config <project_dir>` for Dockerfile/Terraform files
   - Walk up to `.git` to find project root (same pattern as `shared/scan.sh`)
   - Deduplicates against DF001/DF002 findings by line
   - Tests: `test_rules_trivy.py` with mock subprocess

2. **Add VGL-N001** — nginx security headers (`src/vigil/rules/nginx.py`)
   - `applies_to`: `nginx.conf`, `*.nginx`, `sites-available/*`, `sites-enabled/*`
   - Checks: `server_tokens off`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, TLS 1.2+ only
   - Tests: `test_rules_nginx.py` with safe/unsafe nginx fixture files

3. **Add VGL-DF003** — secrets in Dockerfile ENV/ARG layers
   - `ENV SECRET=value` or `ARG token` persists in image history
   - Add to `src/vigil/rules/dockerfile.py`

4. **SARIF output** — add `report_sarif(results)` to `reporter.py`
   - SARIF v2.1.0 schema; enables GitHub Advanced Security PR annotations
   - Add `--format sarif` to CLI

5. **`vigil init` command** — writes hook into `.claude/settings.json` automatically
   - `vigil init` detects Claude Code settings file, adds PostToolUse hook entry
   - Zero-friction onboarding: install + `vigil init` = done

6. **Claude Code plugin manifest** (`plugin/manifest.json` + `plugin/README_INSTALL.md`)
   - Research current Claude Code marketplace plugin spec before writing
   - README_INSTALL.md: 3-step install (pip install vigil → vigil init → reload)

---

## Phase Status

| Phase | Status | Details |
|-------|--------|---------|
| Phase 0 — Core engine | ✅ Complete | 12 rules, 31 tests, CLI, hook, Gitea |
| Phase 1 — Rule expansion + Claude Code marketplace | ⏳ Next | VGL-T001, N001, DF003, SARIF, plugin manifest |
| Phase 2 — VS Code extension + config | ⏳ Future | `.vigilrc`, custom rule DSL, K8s/IAM rules |
| Phase 3 — GitHub Actions + Team dashboard | ⏳ Future | **H1B gated** — build now, revenue after LLC |
| Phase 4 — Enterprise + JetBrains | ⏳ Future | SOC2, SIEM, on-prem |

---

## Key Files

| File | Purpose |
|---|---|
| `src/vigil/rules/base.py` | `Severity`, `Finding`, `Rule` ABC — extend this for every new rule |
| `src/vigil/rules/docker.py` | VGL-D001 — the unique port binding rule; the beachhead story |
| `src/vigil/engine.py` | Orchestrates all checks; `blocking()` determines exit code |
| `src/vigil/cli.py` | `vigil scan` entry point |
| `plugin/hook.sh` | Claude Code PostToolUse hook |
| `PRODUCT_VISION.md` | Full 4-phase roadmap, market gap evidence, revenue model |

---

## Blockers

None. Phase 1 ready to start.
