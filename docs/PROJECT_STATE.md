# Vigil — Project State Snapshot
**Captured: 2026-06-26 · 18 rules · 102 tests · Gitea 0cc257f**

---

```
╔══════════════════════════════════════════════════════════════════════════════════╗
║                          VIGIL — CURRENT STATE                                  ║
║                     18 rules · 102 tests · Gitea 0cc257f                        ║
╚══════════════════════════════════════════════════════════════════════════════════╝

 ┌─────────────────────────────── ARCHITECTURE ──────────────────────────────────┐
 │                                                                                │
 │   AI writes file                                                               │
 │        │                                                                       │
 │        ▼                                                                       │
 │  ┌──────────────┐   PostToolUse    ┌─────────────────────────────────────┐    │
 │  │  Claude Code │ ─────────────▶  │          plugin/hook.sh             │    │
 │  │  (any AI IDE)│                  │  reads file_path from stdin JSON    │    │
 │  └──────────────┘                  └──────────────┬──────────────────────┘    │
 │                                                   │                            │
 │                                                   ▼                            │
 │                                    ┌─────────────────────────┐                │
 │                                    │    vigil scan <file>    │                │
 │                                    │   (stdlib-only Python)  │                │
 │                                    └──────────────┬──────────┘                │
 │                                                   │                            │
 │                          ┌────────────────────────┼──────────────────────┐    │
 │                          ▼                        ▼                      ▼    │
 │                   ┌─────────────┐         ┌────────────┐        ┌───────────┐ │
 │                   │ load_config │         │   Engine   │        │ Reporter  │ │
 │                   │  .vigilrc   │────────▶│ scan/block │        │ terminal  │ │
 │                   │ ancestor    │         │ 18 rules   │        │ JSON      │ │
 │                   │ walk        │         └─────┬──────┘        │ SARIF 2.1 │ │
 │                   └─────────────┘               │               └───────────┘ │
 │                                                 ▼                              │
 │                                    ┌────────────────────────┐                 │
 │                                    │    exit 0 / 1 / 2      │                 │
 │                                    │  0 = clean             │                 │
 │                                    │  1 = advisory only     │                 │
 │                                    │  2 = CRITICAL/HIGH     │                 │
 │                                    │      ← BLOCKS write    │                 │
 │                                    └────────────────────────┘                 │
 └────────────────────────────────────────────────────────────────────────────────┘


 ┌─────────────────────────────── RULE CORPUS ───────────────────────────────────┐
 │                                                                                │
 │  VGL-S001  CRITICAL  AWS access key (AKIA…)              ✅ Phase 0           │
 │  VGL-S002  CRITICAL  Hardcoded password                   ✅ Phase 0           │
 │  VGL-S003  CRITICAL  Hardcoded API key                    ✅ Phase 0           │
 │  VGL-S004  CRITICAL  Hardcoded token                      ✅ Phase 0           │
 │  VGL-I001  CRITICAL  eval() / exec() injection            ✅ Phase 0           │
 │  VGL-I002  HIGH      subprocess(shell=True)               ✅ Phase 0           │
 │  VGL-I003  HIGH      os.system()                          ✅ Phase 0           │
 │  VGL-D001  CRITICAL  docker-compose "PORT:PORT" → 0.0.0.0 ✅ Phase 0 ◀ UNIQUE│
 │  VGL-DF001 HIGH      Dockerfile running as root           ✅ Phase 0           │
 │  VGL-DF002 MEDIUM    Dockerfile unpinned :latest          ✅ Phase 0           │
 │  VGL-DEP001 HIGH     Python CVEs via pip-audit            ✅ Phase 0           │
 │  VGL-DEP002 HIGH     Critical npm CVEs via npm audit      ✅ Phase 0           │
 │  ─────────────────────────────────────────────────────────────────────────    │
 │  VGL-DF003 HIGH      ENV/ARG secret baked into image      ✅ Phase 1           │
 │  VGL-N001  HIGH      nginx missing headers / weak TLS     ✅ Phase 1           │
 │  VGL-T001  HIGH      Trivy IaC deep scan (Dockerfile/TF)  ✅ Phase 1           │
 │  ─────────────────────────────────────────────────────────────────────────    │
 │  VGL-D002  HIGH      docker-compose env block secrets     ✅ Phase 2           │
 │  VGL-K001  CRITICAL  K8s privileged/hostNetwork/hostPID   ✅ Phase 2           │
 │  VGL-IAM001 CRITICAL IAM "Action":"*" / "Resource":"*"   ✅ Phase 2           │
 │                                                                                │
 │            18 rules total                                                      │
 └────────────────────────────────────────────────────────────────────────────────┘


 ┌──────────────────────────────── TEST SUITE ───────────────────────────────────┐
 │                                                                                │
 │  tests/test_engine.py            12 tests   engine scan, scan_dir, blocking   │
 │  tests/test_reporter.py           8 tests   SARIF 2.1.0 output format         │
 │  tests/test_rules_secrets.py     11 tests   VGL-S001–S004, VGL-I001–I003      │
 │  tests/test_rules_docker.py      17 tests   VGL-D001 (9) + VGL-D002 (8)       │
 │  tests/test_rules_dockerfile.py   9 tests   VGL-DF001, DF002, DF003           │
 │  tests/test_rules_nginx.py        9 tests   VGL-N001                          │
 │  tests/test_rules_trivy.py        8 tests   VGL-T001 (mocked subprocess)      │
 │  tests/test_config.py            11 tests   .vigilrc load + ancestor walk     │
 │  tests/test_rules_k8s.py          9 tests   VGL-K001                          │
 │  tests/test_rules_iam.py          9 tests   VGL-IAM001                        │
 │  ─────────────────────────────────────────────────────────────────────────    │
 │                               102 tests  ·  0.11s  ·  all passing ✅          │
 └────────────────────────────────────────────────────────────────────────────────┘


 ┌──────────────────────────────── PHASE ROADMAP ────────────────────────────────┐
 │                                                                                │
 │  Phase 0 ██████████  DONE   Core engine, 12 rules, CLI, hook, Gitea          │
 │  Phase 1 ██████████  DONE   +3 rules, SARIF, vigil init, plugin manifest     │
 │  Phase 2 ████████░░  75%    .vigilrc ✅  D002 ✅  K001 ✅  IAM001 ✅          │
 │                             VS Code ext ⏳  PyPI publish ⏳  --watch ⏳        │
 │  Phase 3 ░░░░░░░░░░  TODO   GitHub Actions, Team dashboard (H1B gated)       │
 │  Phase 4 ░░░░░░░░░░  TODO   JetBrains, SOC2, Enterprise                      │
 │                                                                                │
 └────────────────────────────────────────────────────────────────────────────────┘


 ┌────────────────────────────── DISTRIBUTION ───────────────────────────────────┐
 │                                                                                │
 │  LIVE     Claude Code hook   plugin/hook.sh wired to ~/.claude/settings.json  │
 │  LIVE     Gitea CI           .gitea/workflows/test.yml — pytest+bandit+trivy  │
 │  LIVE     security_runner    weekly bandit+gitleaks+semgrep on src/vigil/     │
 │                                                                                │
 │  NEXT     PyPI               pip install vigil  (free, H1B-safe)              │
 │  NEXT     VS Code extension  vigil-vscode — reaches Copilot/Cursor users      │
 │  FUTURE   Claude marketplace plugin/manifest.json already written             │
 │  FUTURE   GitHub Actions     vigil-action — PR-level scan w/ SARIF upload     │
 │                                                                                │
 └────────────────────────────────────────────────────────────────────────────────┘


 ┌────────────────────────────── MARKET POSITION ────────────────────────────────┐
 │                                                                                │
 │          Checkov   Trivy   Semgrep   Snyk   │  Vigil                          │
 │  ─────────────────────────────────────────────────────────────────────        │
 │  Docker port bind   ❌       ❌       ❌     ❌  │  ✅ VGL-D001 ← UNIQUE        │
 │  At-generation      ❌       ❌       ❌     ❌  │  ✅ PostToolUse              │
 │  AI pattern rules   ❌       ❌       ❌     ❌  │  ✅ 18 rules                 │
 │  K8s in IDE         ❌       ❌       ❌     ✅  │  ✅ VGL-K001                 │
 │  Dep CVE instant    ❌       ✅       ❌     ✅  │  ✅ DEP001/002               │
 │  SARIF output       ✅       ✅       ✅     ✅  │  ✅                          │
 │  Zero dependencies  ❌       ❌       ❌     ❌  │  ✅ stdlib-only              │
 │                                                                                │
 └────────────────────────────────────────────────────────────────────────────────┘

 License: BUSL 1.1 → MIT in 4 years  ·  H1B-safe: publish free, defer revenue
 Repo: http://100.80.161.44:3000/fwss/vigil  ·  Owner: Prem Kumar Akula (FWSS)
```
