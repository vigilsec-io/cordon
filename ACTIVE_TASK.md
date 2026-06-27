# Vigil — Active Task State

> **Purpose:** Read at the START of every session to resume exactly where the last session ended.
> Update whenever a task step completes or a session closes.

---

## Last Updated: 2026-06-27

**Status:** 36 rules, 188 tests, all passing. PyPI package (`vigilsec` 0.1.0) published. README.md written. Cloudflare redirect `thefwss.com/vigil` → Typeform live. Medium article reformatted for Medium's native editor. Next: VS Code extension scaffold.

---

## Phase 0 — Completed (2026-06-26)

1. ✅ Core engine + 12 rules (VGL-S/I/D/DF/DEP), CLI, hook, Gitea
2. ✅ 31 tests, pyproject.toml, .gitea/workflows/test.yml, PRODUCT_VISION.md

---

## Phase 1 — Completed (2026-06-26)

1. ✅ VGL-DF003 (ENV secret baking), VGL-N001 (nginx headers), VGL-T001 (trivy)
2. ✅ SARIF output, `vigil init` command, plugin manifest + README_INSTALL.md
3. ✅ 65 tests total

---

## Phase 2 — Completed (2026-06-26/27)

1. ✅ **`.vigilrc` config** — `src/vigil/config.py`; disabled_rules, min_severity, exclude_paths, telemetry
2. ✅ **VGL-D002** — docker-compose `environment:` hardcoded secrets; HIGH severity
3. ✅ **VGL-K001** — K8s `privileged: true` (CRITICAL), `hostNetwork/hostPID/hostIPC` (HIGH)
4. ✅ **VGL-IAM001** — IAM `"Action": "*"` (CRITICAL), `"Resource": "*"` (HIGH); multi-line list
5. ✅ **VGL-DF003 URL extension** (ticket #1) — credential-embedded URLs in ENV/ARG values
6. ✅ **VGL-S005–S010** (ticket #3) — JWT secret, PEM key, DB credential URLs, Stripe, Slack, provider keys
7. ✅ **VGL-PI001–PI004** (ticket #5) — prompt injection patterns in AI-calling code
8. ✅ **VGL-MCP001–MCP003** (ticket #10) — MCP server security (tool poisoning, dynamic descriptions, shell tools)
9. ✅ **VGL-A001–A004** (ticket #12) — excessive agency (LLM→shell, auto-approve, unbounded loops, LLM→file)
10. ✅ **`# vigil: ignore`** — inline suppression in Engine.scan() (mirrors `# noqa` / `# nosec`)
11. ✅ **`vigil feedback` command** — opens thefwss.com/vigil; dim footer in terminal output
12. ✅ **Anonymous telemetry** — `src/vigil/telemetry.py`; records only rule_id + severity + file_ext + ts; local ~/.vigil/events.jsonl; opt-out via VIGIL_NO_TELEMETRY=1 or `telemetry = false` in .vigilrc; 11 tests
13. ✅ **35 rules total** — 169 tests, all passing in 0.17s; pushed to Gitea (c4bf936)
14. ✅ **Gitea tickets closed** — #1, #3, #5, #10, #12 all closed with fix references
15. ✅ **docs/PROJECT_STATE.md** — ASCII architecture diagram + state snapshot
16. ✅ **docs/MEDIUM_ARTICLE.md** — full Medium article draft (3 title variants)
17. ✅ **VGL-S011** — shell script secret inline on subprocess/SSH (`ps aux` leak); `src/vigil/rules/shell.py`; 16 tests; closes Gitea #15
18. ✅ **Typeform waitlist** — `thefwss.com/vigil` Cloudflare redirect → `https://form.typeform.com/to/AEs5yinT`; `vigil feedback` command wired
19. ✅ **README.md** — full install guide, 36-rule catalog, `.vigilrc` reference, `# vigil: ignore` docs, telemetry opt-out, "Adding a Rule" section
20. ✅ **PyPI published** — `vigilsec` 0.1.0 on PyPI; `pip install vigilsec`; `pyproject.toml` updated (BUSL-1.1, project URLs, keywords)
21. ✅ **Medium article reformatted** — `docs/MEDIUM_ARTICLE.md` rewritten for Medium's native editor: no markdown tables, H2/H3 headings, block quotes, prose competitive comparison; 3 title variants; Typeform CTA

---

## Next Steps — Phase 3

**Resume instruction:** Start with step 1.

1. ✅ **VS Code extension scaffold** — `vigil-vscode/` complete; `vigil-security-0.1.0.vsix` built
   - `src/extension.ts` — `onDidSaveTextDocument` → `vigil scan --format json` → inline Diagnostics
   - Status bar: `$(shield) Vigil` / `$(error) Vigil: N CRITICAL/HIGH` / `$(warning) Vigil: N advisory`
   - Settings: `vigil.enabled`, `vigil.scanOnSave`, `vigil.executablePath`, `vigil.minSeverity`
   - Commands: `Vigil: Scan Current File`, `Vigil: Scan Workspace`
   - Auto-detects vigil in PATH, `~/.local/bin`, macOS Python Library paths, `/opt/homebrew/bin`
   - **Next:** test locally via "Install from VSIX", then publish to VS Code Marketplace

2. **GitHub Actions integration** (ticket #2) — `vigil-action/action.yml`
   - `uses: fwss/vigil-action@v1` in any CI workflow
   - SARIF output → GitHub Security tab annotations

3. **`vigil stats` command** — reads `~/.vigil/events.jsonl`; prints top-10 rules by frequency
   - Surfaces: "You've blocked 47 CRITICAL findings. Top rule: VGL-D001 (23 hits)"
   - Data is already captured by telemetry module; just needs the display command

4. ✅ **Medium article published** — live at official account
   - URL: https://medium.com/@rjbdjnf/i-built-12-apps-with-ai-every-one-had-the-same-security-hole-so-i-built-a-tool-that-fixes-it-edf42a9aa546
   - Topics: Artificial Intelligence, Security, Software Engineering, Docker, Python

---

## Remaining Open Tickets (future sprints)

| # | Title | Priority |
|---|-------|----------|
| #2 | GitHub Actions integration | HIGH |
| #4 | `--watch` mode | HIGH |
| #6 | VGL-D003: secrets in Docker Compose volumes | MEDIUM |
| #7 | VGL-DEP003: lockfile integrity check | MEDIUM |
| #8 | VGL-CF001: Cloudflare Tunnel config | MEDIUM |
| #9 | VGL-TF001: Terraform open security groups | MEDIUM |
| #11 | VGL-NET001: raw IP + port in code | LOW |
| #13 | `vigil stats` command | LOW |
| #14 | Pre-commit hook integration | LOW |

---

## Phase Status

| Phase | Status | Details |
|-------|--------|---------|
| Phase 0 — Core engine | ✅ Complete | 12 rules, 31 tests, CLI, hook, Gitea |
| Phase 1 — Rule expansion | ✅ Complete | +3 rules, SARIF, plugin manifest, 65 tests |
| Phase 2 — Config + AI-era rules | ✅ Complete | 35 rules, 169 tests, telemetry, tickets closed |
| Phase 3 — Distribution (VS Code + PyPI) | 🔄 In Progress | PyPI ✅, README ✅, Medium ✅; VS Code ext next |
| Phase 4 — GitHub Actions + Team dashboard | ⏳ Future | H1B gated on revenue features |
| Phase 5 — Enterprise + JetBrains | ⏳ Future | SOC2, SIEM, on-prem |

---

## Key Numbers

| Metric | Value |
|--------|-------|
| Total rules | 36 |
| Total tests | 188 |
| Test runtime | 0.18s |
| Gitea commit | c4bf936 (pre-S011/telemetry/README/PyPI) |
| PyPI package | `vigilsec` 0.1.0 |
| Lines of source | ~1,600 |

---

## Key Files

| File | Purpose |
|---|---|
| `src/vigil/rules/base.py` | `Severity`, `Finding`, `Rule` ABC |
| `src/vigil/rules/docker.py` | VGL-D001 — the unique port binding rule |
| `src/vigil/rules/agency.py` | VGL-A001–A004 — excessive agency (novel AI-era category) |
| `src/vigil/rules/mcp_security.py` | VGL-MCP001–MCP003 — MCP server security |
| `src/vigil/rules/prompt_injection.py` | VGL-PI001–PI004 — prompt injection in AI code |
| `src/vigil/engine.py` | Orchestrates all checks; `blocking()`; `# vigil: ignore` |
| `src/vigil/telemetry.py` | Anonymous local event collection |
| `src/vigil/config.py` | `.vigilrc` loader; VigilConfig dataclass |
| `src/vigil/cli.py` | `vigil scan` + `vigil init` + `vigil feedback` |
| `plugin/hook.sh` | Claude Code PostToolUse hook |
| `docs/MEDIUM_ARTICLE.md` | Ready to publish (needs PyPI link first) |
| `PRODUCT_VISION.md` | Full roadmap, market gap evidence, revenue model |

---

## Blockers

None.
