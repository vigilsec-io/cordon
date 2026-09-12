#!/usr/bin/env bash
# Valca — Claude Code PostToolUse security hook.
# Reads the written file path from hook stdin (JSON), runs valca scan on it.
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

# Locate vigil executable
VIGIL=""
for candidate in \
    "$(command -v valca 2>/dev/null)" \
    "$HOME/.valca/venv/bin/valca" \
    "$HOME/.vigil/venv/bin/vigil" \
    "/usr/local/bin/vigil" \
    "/opt/homebrew/bin/vigil" \
    "$(dirname "$0")/../venv/bin/vigil"
do
    if [ -x "$candidate" ] 2>/dev/null; then
        VIGIL="$candidate"
        break
    fi
done

if [ -n "$VIGIL" ]; then
    "$VIGIL" scan "$FILE"
    exit $?
fi

# vigil not found — install with: pip install valca && valca init
exit 0
