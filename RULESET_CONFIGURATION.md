# GitHub Ruleset Configuration for agent-bom

## 🎯 Purpose

Create a reusable branch protection ruleset that applies across all repositories in the `agent-bom` organization.

---

## 📋 Ruleset Configuration

### Basic Settings

| Setting | Value |
|---------|-------|
| **Ruleset Name** | `main-branch-protection` |
| **Enforcement** | Active |
| **Target** | All repositories (current + future) |
| **Target Branches** | `main` (default branch) |

---

## 🛡️ Rules Configuration

### 1. Restrict Deletions
✅ **Enabled**
- Prevents accidental deletion of protected branches

### 2. Require Pull Request Before Merging
✅ **Enabled**

**Settings:**
- **Required approvals:** `0` (solo dev) or `1` (team)
- **Dismiss stale reviews:** Yes
- **Require review from Code Owners:** No (unless you add CODEOWNERS file)
- **Require approval of most recent push:** No
- **Require conversation resolution:** Yes

### 3. Require Status Checks to Pass
✅ **Enabled**

**Settings:**
- **Require branches to be up to date:** Yes
- **Required status checks:**
  ```
  - Lint and Type Check
  - Unit Tests (3.10)
  - Unit Tests (3.11)
  - Unit Tests (3.12)
  - Build Docker Image
  - Scan agent-bom (Dogfooding)
  ```

**Note:** These will appear after the first workflow run. Add them when available.

### 4. Block Force Pushes
✅ **Enabled**
- Prevents `git push --force` to protected branches
- Maintains clean git history

### 5. Require Linear History (Optional)
⚪ **Disabled** (for now)
- Can enable later if you want to enforce squash/rebase merges
- Prevents merge commits

### 6. Require Deployments to Succeed (Optional)
⚪ **Disabled**
- Enable if you add deployment workflows

### 7. Require Signed Commits (Optional)
⚪ **Disabled**
- Enable for maximum security
- Requires GPG key setup

---

## 👥 Bypass Permissions

### Who Can Bypass?

**Recommended: No one**
- Leave bypass list empty
- Even admins must follow the rules
- Ensures consistent quality

**Alternative: Emergency Access**
- Add yourself as a bypass actor
- Use only for critical hotfixes
- Document why bypass was used

---

## 🌐 Target Configuration

### All Repositories (Recommended)
```
Target: All repositories
```

**Pros:**
- Automatically applies to new repos
- Consistent protection across org
- Single place to manage

**Cons:**
- Affects all repos (including experimental ones)
- Less flexibility per repo

### Specific Repositories
```
Include: agent-bom, agent-bom-cli, agent-bom-web
```

**Pros:**
- Granular control
- Can exclude experimental repos

**Cons:**
- Must update when creating new repos
- More management overhead

---

## 🔧 Implementation Steps

### Step 1: Create Ruleset

1. Go to: https://github.com/organizations/agent-bom/settings/rules
   - OR: https://github.com/agent-bom/agent-bom/settings/rules (repo-level)

2. Click **"New ruleset"** → **"New branch ruleset"**

3. Configure according to table above

4. Click **"Create"**

### Step 2: Verify Ruleset

1. Check ruleset appears in list: https://github.com/organizations/agent-bom/settings/rules

2. Test by trying to push to main:
   ```bash
   git checkout main
   echo "test" >> README.md
   git add README.md
   git commit -m "test direct push"
   git push origin main  # Should be rejected ❌
   ```

3. Verify PR workflow still works:
   ```bash
   git checkout -b test/ruleset-verification
   echo "test" >> README.md
   git add README.md
   git commit -m "test via PR"
   git push -u origin test/ruleset-verification  # Should work ✅
   ```

### Step 3: Add Status Checks

After first workflow run:

1. Go back to ruleset: https://github.com/organizations/agent-bom/settings/rules

2. Edit `main-branch-protection`

3. Under "Require status checks to pass", add:
   - Lint and Type Check
   - Unit Tests (3.10)
   - Unit Tests (3.11)
   - Unit Tests (3.12)
   - Build Docker Image

4. Click **"Save changes"**

---

## 📊 Ruleset vs Classic Protection

| Feature | Classic | Ruleset |
|---------|---------|---------|
| Per-branch rules | ✅ | ✅ |
| Org-wide rules | ❌ | ✅ |
| Apply to multiple repos | ❌ | ✅ |
| Target by pattern | ✅ | ✅ |
| Bypass controls | Basic | Advanced |
| Audit logging | Basic | Enhanced |
| Future-proof | ❌ | ✅ |

---

## 🎯 Example Rulesets for Different Scenarios

### Solo Developer (Current)
```yaml
Name: main-branch-protection
Target: All repositories
Branches: main
Required approvals: 0
Status checks: All CI/CD
Bypass: None
```

### Small Team (Future)
```yaml
Name: main-branch-protection
Target: All repositories
Branches: main, develop
Required approvals: 1
Status checks: All CI/CD
Bypass: Team leads only
```

### Enterprise (Future)
```yaml
Name: production-protection
Target: Production repos
Branches: main, release/*
Required approvals: 2
Status checks: All CI/CD + Security scans
Bypass: None (including admins)
Signed commits: Required
```

---

## 🔍 Monitoring and Compliance

### View Ruleset Activity

1. Go to: https://github.com/organizations/agent-bom/settings/rules

2. Click on ruleset name

3. View:
   - Enforcement status
   - Bypass events
   - Applied repositories

### Audit Log

Organization audit log tracks:
- Ruleset creation/modification
- Bypass usage
- Rule violations

Access at: https://github.com/organizations/agent-bom/settings/audit-log

---

## 🆘 Troubleshooting

### "Ruleset not applying to repository"

**Cause:** Repository might be excluded or ruleset inactive

**Fix:**
1. Check ruleset status (Active/Disabled)
2. Verify repository is in target list
3. Check branch name matches pattern

### "Can't push to feature branch"

**Cause:** Ruleset might be targeting wrong branches

**Fix:**
1. Edit ruleset
2. Ensure "Include" only has `main`
3. Check "Exclude" doesn't have wildcard

### "Need to bypass for emergency fix"

**Option 1:** Temporary bypass
1. Edit ruleset
2. Add yourself to bypass list
3. Push fix
4. Remove yourself from bypass list

**Option 2:** Disable ruleset
1. Set enforcement to "Disabled"
2. Push fix
3. Re-enable enforcement

---

## 📚 Resources

- [GitHub Rulesets Documentation](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets)
- [Migrating from Branch Protection to Rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/migrating-from-branch-protection-rules-to-rulesets)
- [Organization Rulesets](https://docs.github.com/en/organizations/managing-organization-settings/managing-rulesets-for-repositories-in-your-organization)

---

## ✅ Checklist

- [ ] Created ruleset at org level
- [ ] Set enforcement to "Active"
- [ ] Targeted all repositories
- [ ] Configured branch pattern (main)
- [ ] Enabled required protections
- [ ] Added status checks (after workflow runs)
- [ ] Tested by attempting direct push to main (should fail)
- [ ] Verified PR workflow still works
- [ ] Documented ruleset in this file

**Status:** Ready for production use! 🚀
