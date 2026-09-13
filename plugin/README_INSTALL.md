# Vigil — Claude Code Plugin Install

Vigil intercepts every file Claude writes and blocks it if CRITICAL or HIGH security findings are detected. No config required.

## 3-Step Install

```bash
# 1. Install
pip install vigil

# 2. Wire the Claude Code hook (project-level)
cd /your/project
vigil init

# 3. Reload Claude Code
# Close and reopen the Claude Code session. Done.
```

For a user-wide install (applies to all projects):
```bash
vigil init --global
```

## What it catches

| Rule | Severity | What triggers it |
|------|----------|-----------------|
| VGL-D001 | CRITICAL | docker-compose port binding without `127.0.0.1:` prefix |
| VGL-S001 | CRITICAL | AWS access key in source code |
| VGL-S002 | CRITICAL | Hardcoded password |
| VGL-S003 | HIGH | Hardcoded API key |
| VGL-S004 | HIGH | Hardcoded token |
| VGL-I001 | CRITICAL | `eval(user_input)` injection |
| VGL-I002 | HIGH | `subprocess.run(..., shell=True)` |
| VGL-I003 | HIGH | `os.system()` call |
| VGL-DF001 | HIGH | Dockerfile missing USER directive (runs as root) |
| VGL-DF002 | MEDIUM | Dockerfile `FROM python:latest` (unpinned) |
| VGL-DF003 | HIGH | `ENV PASSWORD=secret` or `ARG TOKEN=default` baked into image |
| VGL-N001 | HIGH | nginx missing X-Frame-Options / weak TLS |
| VGL-T001 | HIGH | Trivy IaC deep scan (Dockerfile, Terraform) |
| VGL-DEP001 | HIGH | pip-audit CVE in requirements.txt |
| VGL-DEP002 | HIGH | npm audit CVE in package.json |

## Exit codes

- `0` — clean
- `1` — advisory findings (MEDIUM/LOW/INFO) — write allowed
- `2` — CRITICAL or HIGH — **Claude Code blocks the write inline**

## Manual hook setup

If `vigil init` can't find `hook.sh`, add this to `.claude/settings.json`:

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "/absolute/path/to/vigil/plugin/hook.sh"
          }
        ]
      }
    ]
  }
}
```

## Scan without the hook

```bash
vigil scan path/to/file.yml          # terminal output
vigil scan path/to/project/ --format json   # JSON
vigil scan path/to/project/ --format sarif  # SARIF 2.1.0 (GitHub Advanced Security)
```
