# Vigil — Active Task State

> **Purpose:** Read at the START of every session to resume exactly where the last session ended.
> Update whenever a task step completes or a session closes.

---

## Last Updated: 2026-06-27

**Status:** Phase 2 core rules complete. 102/102 tests passing. Gitea at d8a0713 (VGL-I001 false positive fix — model.eval() excluded via negative lookbehind). Shield-ecosystem: 0 Vigil findings. Vigil hook wired in ~/.claude/settings.json. Next: VS Code extension scaffold.

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

## Phase 1 — Completed This Session (2026-06-26)

1. ✅ **VGL-DF003** — `ENV/ARG` secret layer baking rule added to `dockerfile.py`
2. ✅ **VGL-N001** — nginx security headers + weak TLS rule (`src/vigil/rules/nginx.py`)
3. ✅ **VGL-T001** — trivy IaC deep-scan rule (`src/vigil/rules/trivy.py`)
4. ✅ **SARIF output** — `report_sarif()` in `reporter.py` + `--format sarif` CLI flag
5. ✅ **`vigil init` command** — wires PostToolUse hook into `.claude/settings.json`
6. ✅ **Plugin manifest** — `plugin/manifest.json` + `plugin/README_INSTALL.md`
7. ✅ **34 new tests** — 65 total (was 31); all passing in 0.10s
8. ✅ **`__init__.py`** — DEFAULT_RULES updated with 3 new rules (DF003, N001, T001)

---

## Phase 2 — In Progress (2026-06-26)

1. ✅ **`.vigilrc` config file** — `src/vigil/config.py`; `VigilConfig` dataclass; walks up to filesystem root; child precedence; invalid TOML safe-defaults; 11 tests
2. ✅ **VGL-D002** — docker-compose `environment:` block hardcoded secrets; list + mapping style; variable refs skipped; HIGH severity; 8 tests
3. ✅ **`engine.py`** — `scan_dir(extra_skip=)` param; merged with defaults
4. ✅ **`cli.py`** — loads `.vigilrc`; filters disabled rules; `extra_skip`; `effective_sev` logic (--severity overrides min_severity)
5. ✅ **VGL-K001** — K8s `privileged: true` (CRITICAL), `hostNetwork/hostPID/hostIPC: true` (HIGH); 9 tests
6. ✅ **VGL-IAM001** — IAM `"Action": "*"` (CRITICAL), `"Resource": "*"` (HIGH); inline + multi-line list; 9 tests
7. ✅ **18 rules total** — 102 tests, all passing; pushed to Gitea (d915bc8)

---

## Next Steps — Phase 2 Remaining + Phase 3 Prep

**Resume instruction:** Start with step 1.

1. **VS Code extension scaffold** (`vigil-vscode/`) — `package.json` + `extension.ts` stub
   - Trigger: `onDidSaveTextDocument` → `vigil scan <file>` → inline `vscode.Diagnostic` on any CRITICAL/HIGH
   - Entry point: `extension.ts` calls `child_process.exec(vigil scan --format json ...)`
   - `package.json`: `engines.vscode`, `contributes.commands` (Vigil: Scan File), `activationEvents`
   - Build: `vsce package` → `.vsix`; test via "Install from VSIX" in VS Code

2. **PyPI publish prep** — `python3 -m build && twine check dist/*`
   - Ensure `pyproject.toml` has `[project.urls]` + long description from README
   - Upload with `twine upload dist/*` (H1B-safe — free open-source package)

3. **`--watch` mode** — `vigil scan --watch <dir>` using `watchfiles` or polling loop

4. **Phase 2 status update in PRODUCT_VISION.md** — mark VGL-K001, VGL-IAM001 done

---

## Phase Status

| Phase | Status | Details |
|-------|--------|---------|
| Phase 0 — Core engine | ✅ Complete | 12 rules, 31 tests, CLI, hook, Gitea |
| Phase 1 — Rule expansion + Claude Code marketplace | ✅ Complete | +3 rules (DF003/N001/T001), SARIF, plugin manifest, 65 tests |
| Phase 2 — Config + new rules | 🔄 In progress | .vigilrc ✅, VGL-D002 ✅, VGL-K001 ✅, VGL-IAM001 ✅; VS Code ext next |
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
