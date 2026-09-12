#!/usr/bin/env bash
# Vigil — Claude Code PostToolUse security hook.
# Reads the written file path from hook stdin (JSON), runs vigil scan on it.
# Exits 2 on CRITICAL/HIGH to block the write and surface findings inline.
#
# Install: add to .claude/settings.json PostToolUse hook on Write|Edit matcher,
# pointing to this file. See vigil/plugin/README_INSTALL.md.

set -euo pipefail

FILE=$(python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    print(d.get('tool_input', {}).get('file_path', ''))
except Exception:
    print('')
" 2>/dev/null)

if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
    exit 0
fi

# Path boundary check — never scan outside the project root, even if a crafted
# path (traversal, symlink) somehow reaches the hook. Skip silently if outside.
REAL_FILE=$(realpath "$FILE" 2>/dev/null) || exit 0
PROJECT_ROOT=$(realpath "${VIGIL_PROJECT_ROOT:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}" 2>/dev/null) || exit 0
case "$REAL_FILE" in
    "$PROJECT_ROOT"/*) ;;   # within root — OK
    *) exit 0 ;;            # outside root — skip silently
esac

# Size guard — legitimate source files are rarely >1MB; skip large/generated
# files rather than risk a slow regex pass blocking the coding session.
FILE_SIZE=$(wc -c < "$REAL_FILE" 2>/dev/null || echo 0)
if [ "$FILE_SIZE" -gt 1048576 ]; then
    exit 0
fi

# Locate vigil executable
VIGIL=""
for candidate in \
    "$(command -v valca 2>/dev/null)" \
    "$(command -v vigil 2>/dev/null)" \
    "$HOME/.valca/venv/bin/valca" \
    "$(dirname "$0")/../venv/bin/valca" \
    "$HOME/.vigil/venv/bin/vigil" \
    "/usr/local/bin/vigil" \
    "/opt/homebrew/bin/vigil" \
    "$(dirname "$0")/../venv/bin/vigil"
do
    # Executable is not enough: a stale entry-point shim from an older install
    # stays executable but fails to import, exits non-zero, and the write is then
    # allowed through. A scanner that silently stops scanning is the worst failure
    # this tool can have, so each candidate must prove it runs.
    if [ -x "$candidate" ] 2>/dev/null && "$candidate" --help >/dev/null 2>&1; then
        VIGIL="$candidate"
        break
    fi
done

if [ -z "$VIGIL" ]; then
    # Nothing runnable was found. Exiting 0 keeps the hook from blocking people
    # who have not installed Valca — but say so on stderr, because a scanner that
    # goes quiet is indistinguishable from a scanner that found nothing.
    echo "valca: no working executable found — files are NOT being scanned." >&2
    echo "valca: install with 'pip install valca' then run 'valca init'." >&2
    exit 0
fi

if [ -n "$VIGIL" ]; then
    # Strip known AI/VCS credential env vars and bound execution time via
    # Python's subprocess timeout — portable across macOS/Linux, unlike the
    # GNU coreutils `timeout` command which isn't installed on stock macOS.
    # Output streams straight through (no capture) so Claude Code still sees
    # it live; exit code passes through unchanged.
    set +e
    python3 - "$VIGIL" "$REAL_FILE" << 'PYEOF'
import subprocess, sys, os

vigil_bin, target_file = sys.argv[1], sys.argv[2]
env = os.environ.copy()
for var in (
    "ANTHROPIC_API_KEY", "GITHUB_TOKEN", "GH_TOKEN", "OPENAI_API_KEY",
    "GEMINI_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
):
    env.pop(var, None)

try:
    result = subprocess.run([vigil_bin, "scan", target_file], env=env, timeout=30)
    sys.exit(result.returncode)
except subprocess.TimeoutExpired:
    print("vigil: scan timed out after 30s — skipping", file=sys.stderr)
    sys.exit(0)
PYEOF
    EXIT_CODE=$?
    set -e
    exit "$EXIT_CODE"
fi

# vigil not found — install with: pip install vigilsec && vigil init
exit 0
