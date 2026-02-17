# Git Workflow for agent-bom

## 🎯 Branch Strategy

**Never work directly on `main`!** Always use feature branches.

```
main (protected)
  ├── feature/add-enrichment
  ├── feature/snowflake-integration
  ├── bugfix/fix-parsing-error
  └── docs/update-readme
```

---

## 📋 Workflow Steps

### 1. Start New Work

Always create a feature branch from `main`:

```bash
# Update main first
git checkout main
git pull origin main

# Create and switch to new feature branch
git checkout -b feature/your-feature-name

# Examples:
git checkout -b feature/add-snowflake-scanning
git checkout -b bugfix/fix-nvd-timeout
git checkout -b docs/deployment-guide
```

### 2. Make Changes

Work on your feature:

```bash
# Make changes to files
# ...

# Stage changes
git add src/agent_bom/discovery/snowflake.py
git add tests/test_snowflake.py

# Commit (NO Co-Authored-By lines!)
git commit -m "Add Snowflake Cortex agent discovery

- Implement snowflake-connector-python integration
- Query INFORMATION_SCHEMA.CORTEX_AGENTS
- Parse agent configs and extract packages
- Add CLI flags: --snowflake-account, --snowflake-user
"
```

### 3. Push Feature Branch

```bash
# Push to remote
git push -u origin feature/your-feature-name
```

### 4. Create Pull Request

**Option A: Using GitHub CLI (Recommended)**

```bash
gh pr create \
  --title "Add Snowflake Cortex scanning" \
  --body "### What's Added

- Snowflake connector integration
- CORTEX_AGENTS discovery
- CLI flags for Snowflake authentication

### Testing
- [ ] Tested with live Snowflake account
- [ ] Unit tests pass
- [ ] Integration tests pass
" \
  --base main \
  --head feature/your-feature-name
```

**Option B: Via GitHub Web**

1. Push your branch: `git push -u origin feature/your-feature-name`
2. Go to: https://github.com/agent-bom/agent-bom
3. Click "Compare & pull request"
4. Fill in title and description
5. Click "Create pull request"

### 5. Review and Merge

1. **Review** the PR (check diff, run tests)
2. **Merge** via GitHub web UI
3. **Delete** the feature branch after merge

```bash
# After PR is merged, clean up locally
git checkout main
git pull origin main
git branch -d feature/your-feature-name
```

---

## 🔄 Example: Full Workflow

```bash
# 1. Start new feature
git checkout main
git pull origin main
git checkout -b feature/add-epss-enrichment

# 2. Make changes
# Edit files...
git add src/agent_bom/enrichment.py
git commit -m "Add EPSS exploit prediction scoring"

# 3. Push branch
git push -u origin feature/add-epss-enrichment

# 4. Create PR
gh pr create --title "Add EPSS enrichment" --base main

# 5. After PR merged, clean up
git checkout main
git pull origin main
git branch -d feature/add-epss-enrichment
```

---

## 🛡️ Branch Protection Rules

**Recommended settings for `main` branch:**

Go to: Settings → Branches → Add rule for `main`

- ✅ Require pull request before merging
- ✅ Require approvals: 1 (or 0 if solo developer)
- ✅ Require status checks to pass:
  - `lint` (ruff, mypy)
  - `test` (pytest)
  - `scan-self` (agent-bom dogfooding)
- ✅ Require branches to be up to date
- ✅ Do not allow bypassing the above settings

**This ensures:**
- No direct commits to `main`
- All changes go through PR review
- Tests must pass before merge
- Clean git history

---

## 📝 Commit Message Format

Use **semantic commit messages**:

```
<type>: <short summary>

<detailed description>

<footer>
```

**Types:**
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation only
- `test:` Adding tests
- `refactor:` Code refactoring
- `perf:` Performance improvements
- `chore:` Build/tooling changes

**Examples:**

```bash
# Good commits
git commit -m "feat: add Snowflake Cortex agent discovery

Implements Snowflake connector to query CORTEX_AGENTS table
and extract package dependencies from agent configurations.
"

git commit -m "fix: handle NVD API rate limiting

Add exponential backoff when NVD API returns 429 status.
Fixes issue where scans fail with many CVEs.
"

git commit -m "docs: update DEPLOYMENT.md with Kubernetes examples"

# Bad commits
git commit -m "update stuff"
git commit -m "fix bug"
git commit -m "changes"
```

---

## 🚫 What NOT to Do

❌ **Don't commit directly to main**
```bash
# WRONG
git checkout main
git add .
git commit -m "add feature"
git push origin main
```

✅ **Do this instead**
```bash
# RIGHT
git checkout -b feature/my-feature
git add .
git commit -m "feat: add feature"
git push -u origin feature/my-feature
gh pr create
```

---

## 🔧 Useful Git Commands

### Check current branch
```bash
git branch
git status
```

### Switch branches
```bash
git checkout main
git checkout feature/my-feature
```

### Update local main
```bash
git checkout main
git pull origin main
```

### View branch history
```bash
git log --oneline --graph --all
```

### Undo uncommitted changes
```bash
git restore src/file.py  # Undo changes to file
git restore .            # Undo all changes
```

### Delete local branch
```bash
git branch -d feature/old-feature   # Safe delete (only if merged)
git branch -D feature/old-feature   # Force delete
```

### Delete remote branch
```bash
git push origin --delete feature/old-feature
```

---

## 🎯 Quick Reference

| Task | Command |
|------|---------|
| Create feature branch | `git checkout -b feature/name` |
| Commit changes | `git add . && git commit -m "message"` |
| Push branch | `git push -u origin feature/name` |
| Create PR | `gh pr create` |
| Update main | `git checkout main && git pull` |
| Delete branch | `git branch -d feature/name` |

---

## 📚 Resources

- [GitHub Flow Guide](https://docs.github.com/en/get-started/quickstart/github-flow)
- [Conventional Commits](https://www.conventionalcommits.org/)
- [Git Branching Best Practices](https://git-scm.com/book/en/v2/Git-Branching-Branching-Workflows)

---

**Remember: `main` is sacred. Always use feature branches!** 🛡️
