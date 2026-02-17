# Fix Git Push Error

## Problem

```
! [rejected]        main -> main (non-fast-forward)
error: failed to push some refs
hint: Updates were rejected because the tip of your current branch is behind
```

**Meaning:** Remote has commits you don't have locally (divergent branches)

---

## Solution 1: Pull and Merge (Recommended)

```bash
# 1. See what's on remote
git fetch origin
git log HEAD..origin/main --oneline

# 2. Pull and merge
git pull origin main

# 3. If conflicts, resolve them:
# - Open conflicted files
# - Fix conflicts (look for <<<<<<< HEAD)
# - git add <fixed-files>
# - git commit -m "Merge remote changes"

# 4. Push
git push origin main
```

---

## Solution 2: Pull and Rebase (Cleaner History)

```bash
# 1. Pull with rebase
git pull --rebase origin main

# 2. If conflicts:
# - Fix conflicts in files
# - git add <fixed-files>
# - git rebase --continue

# 3. Push
git push origin main
```

---

## Solution 3: Use Feature Branch (Best Practice)

```bash
# Never push directly to main!

# 1. Create feature branch from current work
git checkout -b feature/security-hardening

# 2. Push feature branch
git push origin feature/security-hardening

# 3. Create PR on GitHub
# - Go to https://github.com/agent-bom/agent-bom
# - Click "Compare & pull request"
# - Review changes
# - Merge via GitHub UI

# 4. Update local main
git checkout main
git pull origin main
```

---

## Quick Fix Script

```bash
#!/bin/bash
# fix-git-push.sh

echo "🔍 Checking what's different..."
git fetch origin

BEHIND=$(git rev-list HEAD..origin/main --count)
AHEAD=$(git rev-list origin/main..HEAD --count)

echo "Your branch is:"
echo "  - $AHEAD commit(s) AHEAD of origin/main"
echo "  - $BEHIND commit(s) BEHIND origin/main"

if [ "$BEHIND" -gt 0 ]; then
    echo ""
    echo "📥 Pulling remote changes..."
    git pull --rebase origin main

    if [ $? -eq 0 ]; then
        echo "✅ Successfully rebased"
        echo "📤 Pushing..."
        git push origin main
        echo "✅ Done!"
    else
        echo "❌ Conflicts during rebase"
        echo "Fix conflicts, then run:"
        echo "  git add <fixed-files>"
        echo "  git rebase --continue"
        echo "  git push origin main"
    fi
else
    echo "✅ No conflicts - pushing..."
    git push origin main
fi
```

Make executable:
```bash
chmod +x fix-git-push.sh
./fix-git-push.sh
```

---

## What Happened?

**Possible causes:**
1. ✅ **GitHub workflow file added via UI** - You added `.github/workflows/ci.yml` manually on GitHub
2. ✅ **Branch protection changes** - GitHub created commits for ruleset setup
3. ✅ **Collaborator pushed** - Someone else pushed to main
4. ✅ **GitHub merge** - A PR was merged via GitHub UI

---

## Prevention

### 1. Use Feature Branch Workflow

```bash
# Always work on feature branches
git checkout -b feature/my-feature
# ... make changes ...
git push origin feature/my-feature
# Create PR on GitHub
```

### 2. Keep Main Updated

```bash
# Before starting new work
git checkout main
git pull origin main
git checkout -b feature/new-feature
```

### 3. Use Makefile Commands

```bash
# See GIT_WORKFLOW.md
make git-sync     # Pull latest from main
make git-feature name=my-feature  # Create feature branch
```

---

## Current Situation

Run this to see what's different:

```bash
git fetch origin
git log --oneline --graph --all --decorate
```

Then choose one of the solutions above.

**Recommended:** Use Solution 3 (feature branch) going forward.
