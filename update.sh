#!/bin/bash
set -e
REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
MSG="${1:-update}"
echo "📦 Deploying: $MSG"
cp "$REPO_DIR/server.js" "$REPO_DIR/../wholesale-state/server.js" 2>/dev/null || true
cp "$REPO_DIR/index.html" "$REPO_DIR/../wholesale-state/public/index.html" 2>/dev/null || true
cd ~/Documents/wholesale-state
git add -A
git commit -m "$MSG"
git push origin main
echo "✅ Pushed — Render will deploy in ~1 min"
