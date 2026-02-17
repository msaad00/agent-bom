# Branch Protection Setup Guide

## 🎯 Goal

Prevent merging to `main` until:
1. ✅ Pull request is reviewed and approved
2. ✅ All CI/CD checks pass (lint, tests, build)
3. ✅ Branch is up-to-date with main

---

## 🌐 Setup via GitHub Web UI

### Step 1: Navigate to Settings

1. Go to: https://github.com/agent-bom/agent-bom/settings/branches
2. Click **"Add branch protection rule"** or **"Add rule"**

### Step 2: Configure Rule for `main`

**Branch name pattern:** `main`

### Step 3: Required Settings

#### ✅ Require a pull request before merging
- Check this box
- **Require approvals:** `1` (or `0` if you're solo and don't want mandatory reviews)
- ✅ **Dismiss stale pull request approvals when new commits are pushed**
- ✅ **Require review from Code Owners** (optional, only if you have CODEOWNERS file)

#### ✅ Require status checks to pass before merging
- Check this box
- ✅ **Require branches to be up to date before merging**
- **Search for status checks:**
  - Type and select: `Lint and Type Check`
  - Type and select: `Unit Tests (3.10)`
  - Type and select: `Unit Tests (3.11)`
  - Type and select: `Unit Tests (3.12)`
  - Type and select: `Build Docker Image`

  *(These will appear after the first workflow run)*

#### ✅ Require conversation resolution before merging
- Check this box (ensures all PR comments are resolved)

#### ✅ Do not allow bypassing the above settings
- Check this box (even admins must follow rules)
- ⚠️ **Exception:** You can uncheck if you need emergency hotfix capability

#### ⚠️ Require linear history (Optional but Recommended)
- Check this box (prevents merge commits, keeps git history clean)

---

## 📋 Recommended Configuration

### Minimal (Solo Developer)

```
✅ Require a pull request before merging
   - Required approvals: 0
✅ Require status checks to pass before merging
   - Require branches to be up to date: Yes
   - Status checks: Lint and Type Check, Unit Tests
✅ Require conversation resolution before merging
```

**Why no approval required?**
- You're the only developer
- Still forces PR workflow (no direct commits to main)
- Still requires all checks to pass

---

### Standard (Team)

```
✅ Require a pull request before merging
   - Required approvals: 1
   - Dismiss stale approvals: Yes
✅ Require status checks to pass before merging
   - Require branches to be up to date: Yes
   - Status checks: All CI/CD checks
✅ Require conversation resolution before merging
✅ Do not allow bypassing
```

---

### Enterprise (Strict)

```
✅ Require a pull request before merging
   - Required approvals: 2
   - Dismiss stale approvals: Yes
   - Require review from Code Owners: Yes
✅ Require status checks to pass before merging
   - Require branches to be up to date: Yes
   - Status checks: All CI/CD checks
✅ Require conversation resolution before merging
✅ Do not allow bypassing
✅ Require linear history
✅ Require signed commits
✅ Include administrators (even admins can't bypass)
```

---

## 🖥️ Setup via GitHub CLI

Unfortunately, GitHub CLI (`gh`) doesn't directly support branch protection rules (as of v2.x). You can use the GitHub API instead:

```bash
# Set branch protection (requires GitHub token with admin:org scope)
gh api repos/agent-bom/agent-bom/branches/main/protection \
  -X PUT \
  -H "Accept: application/vnd.github+json" \
  -f required_status_checks='{"strict":true,"contexts":["Lint and Type Check","Unit Tests (3.10)","Unit Tests (3.11)","Unit Tests (3.12)","Build Docker Image"]}' \
  -f enforce_admins=true \
  -f required_pull_request_reviews='{"required_approving_review_count":1,"dismiss_stale_reviews":true}' \
  -f restrictions=null \
  -f required_conversation_resolution=true \
  -f allow_force_pushes=false \
  -f allow_deletions=false
```

**Easier approach:** Use the web UI (Step 1-3 above)

---

## ✅ Verify Protection is Active

### Via Web UI
1. Go to: https://github.com/agent-bom/agent-bom/settings/branches
2. You should see `main` with protection rules listed

### Via CLI
```bash
gh api repos/agent-bom/agent-bom/branches/main/protection | jq .
```

### Test It
1. Try to push directly to main:
   ```bash
   git checkout main
   echo "test" >> README.md
   git add README.md
   git commit -m "test direct commit"
   git push origin main
   ```

   **Expected:** ❌ Push rejected!

2. Try to merge PR without passing checks:
   - Go to any PR
   - **Expected:** "Merge" button is disabled until checks pass

---

## 🎯 What This Achieves

### Before Protection
```
Developer → git push origin main → ✅ Merged (no review, no checks)
```

### After Protection
```
Developer → feature branch → Push → Create PR
                                      ↓
                                   CI checks run
                                      ↓
                                   ❌ Checks fail? → Fix & push again
                                   ✅ Checks pass?
                                      ↓
                                   Review required? → Get approval
                                      ↓
                                   Merge button enabled → Merge ✅
```

---

## 📸 Example: PR with Required Checks

When branch protection is active, you'll see:

```
✅ Lint and Type Check — Required
✅ Unit Tests (3.10) — Required
✅ Unit Tests (3.11) — Required
✅ Unit Tests (3.12) — Required
⏳ Build Docker Image — In progress
❌ Merge pull request (blocked until all checks pass)
```

---

## 🔧 Troubleshooting

### "Status checks not found"

**Problem:** Can't select status checks when setting up protection

**Solution:**
1. First, run the workflow at least once (push to a PR)
2. Wait for checks to appear in GitHub Actions
3. Then add them to branch protection

### "I need to bypass protection for emergency fix"

**Option 1:** Temporarily disable protection
1. Go to Settings → Branches
2. Edit the rule
3. Uncheck "Do not allow bypassing"
4. Merge your emergency fix
5. Re-enable the setting

**Option 2:** Use a hotfix workflow
```bash
git checkout -b hotfix/critical-fix
# Make fix
git push -u origin hotfix/critical-fix
# Get expedited review
# Merge after minimal checks
```

### "Checks are failing but I need to merge"

**Don't do it!** This defeats the purpose. Instead:
1. Fix the failing checks
2. Push the fix
3. Wait for green checks
4. Then merge

---

## 📚 Additional Resources

- [GitHub Branch Protection Docs](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches)
- [Required Status Checks](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/collaborating-on-repositories-with-code-quality-features/about-status-checks)
- [CODEOWNERS File](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-code-owners)

---

## 🎯 Quick Setup Checklist

- [ ] Go to Settings → Branches
- [ ] Add protection rule for `main`
- [ ] Enable "Require a pull request before merging"
- [ ] Enable "Require status checks to pass before merging"
- [ ] Select required status checks (after first workflow run)
- [ ] Enable "Require conversation resolution"
- [ ] Save changes
- [ ] Test by trying to push to main directly (should fail)

**Done!** 🛡️ Your `main` branch is now protected.
