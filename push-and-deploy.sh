#!/bin/bash
#
# push-and-deploy.sh — Git push + auto deploy
#
# Usage:
#   ./push-and-deploy.sh "commit message"
#   ./push-and-deploy.sh                    # default message

set -e

MSG="${1:-auto-deploy: $(date '+%Y-%m-%d %H:%M')}"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Push & Deploy"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd "$(dirname "$0")"

# 1. Add & commit
git add -A
if git diff --cached --quiet; then
    echo "No changes to commit."
else
    git commit -m "$MSG"
    echo "✅ Committed: $MSG"
fi

# 2. Push to GitHub
git push origin main
echo "✅ Pushed to GitHub"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "If GitHub Actions is configured:"
echo "  → Deploy will start automatically"
echo "  → Check: https://github.com/DrFlach/anonymous-network/actions"
echo ""
echo "For manual deploy via Cloud Shell:"
echo "  gcloud cloud-shell ssh --command='cd ~/anonymous-network && git pull origin main && go build -o anon-router ./cmd/router/ && ./deploy/deploy-cloud.sh --gcloud anon-relay europe-central2-a deploy'"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
