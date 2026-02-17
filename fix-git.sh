#!/bin/bash
# Quick fix for git push error

set -e

echo "🔍 Checking git status..."
git fetch origin

BEHIND=$(git rev-list HEAD..origin/main --count 2>/dev/null || echo "0")
AHEAD=$(git rev-list origin/main..HEAD --count 2>/dev/null || echo "0")

echo ""
echo "📊 Branch status:"
echo "   Local commits ahead:  $AHEAD"
echo "   Remote commits behind: $BEHIND"
echo ""

if [ "$BEHIND" -gt 0 ] && [ "$AHEAD" -gt 0 ]; then
    echo "⚠️  Divergent branches detected!"
    echo ""
    echo "Choose an option:"
    echo "  1) Pull and rebase (recommended - cleaner history)"
    echo "  2) Pull and merge (safer - preserves all commits)"
    echo "  3) Create feature branch (best practice - avoid main)"
    echo "  4) Show what's different"
    echo "  5) Cancel"
    echo ""
    read -p "Enter choice [1-5]: " choice

    case $choice in
        1)
            echo "📥 Pulling with rebase..."
            git pull --rebase origin main
            if [ $? -eq 0 ]; then
                echo "✅ Rebase successful!"
                echo "📤 Pushing..."
                git push origin main
                echo "✅ Done!"
            else
                echo "❌ Conflicts during rebase"
                echo ""
                echo "Fix conflicts, then run:"
                echo "  git add <fixed-files>"
                echo "  git rebase --continue"
                echo "  git push origin main"
            fi
            ;;
        2)
            echo "📥 Pulling with merge..."
            git pull origin main
            if [ $? -eq 0 ]; then
                echo "✅ Merge successful!"
                echo "📤 Pushing..."
                git push origin main
                echo "✅ Done!"
            else
                echo "❌ Conflicts during merge"
                echo ""
                echo "Fix conflicts, then run:"
                echo "  git add <fixed-files>"
                echo "  git commit -m 'Merge remote changes'"
                echo "  git push origin main"
            fi
            ;;
        3)
            BRANCH_NAME="feature/local-changes-$(date +%Y%m%d-%H%M%S)"
            echo "🌿 Creating feature branch: $BRANCH_NAME"
            git checkout -b "$BRANCH_NAME"
            echo "📤 Pushing feature branch..."
            git push origin "$BRANCH_NAME"
            echo ""
            echo "✅ Feature branch created and pushed!"
            echo ""
            echo "Next steps:"
            echo "  1. Go to: https://github.com/agent-bom/agent-bom"
            echo "  2. Click 'Compare & pull request'"
            echo "  3. Review and merge via GitHub UI"
            echo ""
            echo "Then update your local main:"
            echo "  git checkout main"
            echo "  git pull origin main"
            ;;
        4)
            echo "📜 Showing differences..."
            echo ""
            echo "=== Remote commits you don't have ==="
            git log HEAD..origin/main --oneline --graph
            echo ""
            echo "=== Your local commits not on remote ==="
            git log origin/main..HEAD --oneline --graph
            ;;
        5)
            echo "👋 Cancelled"
            exit 0
            ;;
        *)
            echo "❌ Invalid choice"
            exit 1
            ;;
    esac

elif [ "$BEHIND" -gt 0 ]; then
    echo "📥 Remote has new commits. Pulling..."
    git pull origin main
    echo "✅ Up to date!"

elif [ "$AHEAD" -gt 0 ]; then
    echo "📤 Pushing local commits..."
    git push origin main
    echo "✅ Done!"

else
    echo "✅ Already in sync!"
fi
