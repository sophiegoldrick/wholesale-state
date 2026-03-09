#!/bin/bash

# Wholesale State — quick deploy script
# Usage: ./update.sh "your change description"

MSG=${1:-"update dashboard"}

echo "🌿 Deploying: $MSG"

git add -A
git commit -m "$MSG"
git push

echo "✅ Pushed — Railway will deploy in ~60 seconds"
echo "🔗 Check progress at: https://railway.app/dashboard"
