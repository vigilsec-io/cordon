#!/usr/bin/env bash
# Install Valca's git hooks. Run once per clone.
set -euo pipefail
REPO="$(git rev-parse --show-toplevel)"
install -m 0755 "$REPO/scripts/hooks/pre-push" "$REPO/.git/hooks/pre-push"
echo "Installed pre-push gate → .git/hooks/pre-push"
