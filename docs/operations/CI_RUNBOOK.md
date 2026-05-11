# CI Runbook

Operational guidance for the agent-bom CI pipeline. Use this when a PR is
stuck, a workflow fails unexpectedly, or you need to retrigger checks.

---

## Ready PRs blocked behind `main`

### Symptom

A PR is approved, auto-merge is enabled, and all current checks are green, but
GitHub still says **This branch is out-of-date with the base branch** or
**branch update already in progress**. This becomes common when several small
readiness PRs are stacked behind a strict `main` branch protection rule.

### Root cause

`main` advanced after the PR checks started. Branch protection has
`required_status_checks.strict = true`, so GitHub requires the PR head to
include the latest `main` before it can merge. Clicking **Update branch** fixes
the base mismatch, but the resulting synthetic merge commit can produce stale
or canceled check state.

### Permanent fix: auto-refresh ready PRs

`.github/workflows/auto-retrigger-stranded.yml` now runs on every push to
`main`, on a 5-minute schedule, and on manual dispatch. It first runs:

```sh
scripts/refresh_ready_prs.sh
```

The script only refreshes same-repo, non-draft PRs targeting `main`. By default
it further limits writes to PRs with auto-merge already enabled, so exploratory
branches are left alone. The workflow must use `AUTOMATION_GITHUB_TOKEN`, a
dedicated GitHub App token or PAT with repo pull-request/write access. Do not
fall back to `GITHUB_TOKEN` for refresh or retrigger events: GitHub suppresses
workflows triggered by that token, which recreates the frozen-check loop.

Manual one-shot refresh:

```sh
PR_NUMBER=<PR_NUMBER> scripts/refresh_ready_prs.sh
```

Dry-run inspection:

```sh
DRY_RUN=true scripts/refresh_ready_prs.sh
```

If the workflow reports "branch update already in progress", leave it alone; the
next scheduled run will verify whether the head advanced and retrigger checks if
needed.

## Stranded PRs (zero check runs on the current head SHA)

### Symptom

A PR sits in `mergeable_state: blocked` with no checks visible in the GitHub
UI. `gh pr view <N> --json statusCheckRollup` returns `[]`. The PR was passing
its required checks before, then someone clicked **Update branch** (or the
`auto-merge` bot did) and the new merge commit has no workflow runs at all.

### Root cause

GitHub Actions does not recursively trigger workflows from events whose actor
is `GITHUB_TOKEN`. When auto-merge — or the **Update branch** button — pushes
the merge-from-base commit to a PR head, that push is authored by
`GITHUB_TOKEN`. `pull_request` workflows therefore do not fire on that head
SHA, leaving the PR stranded with the previous head's checks marked stale by
`required_status_checks.strict = true`.

This is documented behavior, not an agent-bom-specific bug:
<https://docs.github.com/en/actions/security-guides/automatic-token-authentication#using-the-github_token-in-a-workflow>

### Fix the stranded PR (one-shot)

```sh
scripts/retrigger_stranded_pr.sh <PR_NUMBER>
```

The script:

1. Resolves the PR's current head SHA.
2. Checks whether the canonical required check (`Lint and Type Check`) ran
   against that SHA via `repos/.../commits/<sha>/check-runs`.
3. If any required check is still active, exits without retriggering. Downstream
   jobs such as package build are not created until prerequisite jobs finish.
4. If checks are missing or stale after the run is idle, closes the PR and
   immediately reopens it. This starts `pull_request` workflows only when the
   token is not `GITHUB_TOKEN`.

The script no-ops when the required check is already present, so it is safe to
run on any PR.

### Permanent fix: scheduled auto-retrigger (recommended, already on)

`.github/workflows/auto-retrigger-stranded.yml` runs `scripts/retrigger_stranded_pr.sh`
against every open PR whose current head SHA has zero or stale
`Lint and Type Check` runs. It runs after `main` advances, every five minutes,
and through `workflow_dispatch` for on-demand. Once this workflow is on the
default branch and `AUTOMATION_GITHUB_TOKEN` is configured, stranded PRs
unstrand themselves within five minutes — no operator action required.

Operator-side troubleshooting if a strand persists past ~10 minutes:

- Did the workflow itself run? `gh run list --workflow=auto-retrigger-stranded.yml --limit 5`
- Is `AUTOMATION_GITHUB_TOKEN` configured? Without it the workflow intentionally
  skips write actions because `GITHUB_TOKEN` cannot start required PR checks.
- Was the PR younger than `MIN_AGE_MINUTES` (3 min by default)? It's intentionally
  skipped to give the initial `pull_request` workflow a chance to start.
- Did `gh api commits/{sha}/check-runs` return zero, or is there a
  different check name now? Update `REQUIRED_CHECK` in the workflow if
  the canonical check is renamed.

### Permanent fix alternatives (settings change required)

The auto-refresh/retrigger workflow above is the cheapest path. The following
alternatives still apply if you prefer settings-level fixes; pick one.

| Option | Where | Tradeoff |
|---|---|---|
| **Enable merge queue on `main`** | Settings → Branches → main protection rule → "Require merge queue" | Cleanest. The `merge_group: types: [checks_requested]` trigger already exists in `ci.yml`, so the queue starts working immediately. PRs no longer need to be rebased before merge. |
| **Set `required_status_checks.strict = false`** | Settings → Branches → main protection rule → uncheck "Require branches to be up to date before merging" | Simplest. Removes the need to rebase, so "Update branch" is no longer needed. Loses the guarantee that CI passed against current `main` — relies on post-merge workflows to catch regressions. |
| **Use a GitHub App / PAT for auto-merge** | Replace the bot identity for `Update branch` pushes | Pushes from a non-`GITHUB_TOKEN` identity do fire workflows. Requires creating + scoping a dedicated app or token. |

The merge queue is the recommended option for this repo because the workflow
is already wired for `merge_group`. The three required-status-check workflows
(`ci.yml`, `codeql.yml`, `pr-security-gate.yml`) all declare:

```yaml
on:
  pull_request:
  merge_group:
    types: [checks_requested]
```

so once branch protection is flipped, the queue runs the same checks that
gate PRs today — no workflow edits required.

#### How to flip it (UI-only as of 2026-04)

REST attempts return HTTP 422 "Invalid rule 'merge_queue'" on this repo's
auth path. The Settings UI is the only supported toggle today.

1. https://github.com/msaad00/agent-bom/settings/branches
2. Edit the rule for `main`
3. Check ✅ **Require merge queue**
4. Set merge method to **Squash** and pin the same required status checks
   used today (Lint and Type Check, Test (Python 3.11/3.13/3.14), Build
   Package, Security Scan, CodeQL)
5. Save

Verify with `scripts/enable_merge_queue.sh --check`.

After enabling, "Update branch" disappears from the PR view; the
`Merge when ready` button puts the PR into the queue, which rebases + tests
the merge candidate against current `main` and only fast-forwards once green.
Stranded-CI from `GITHUB_TOKEN` pushes is no longer reachable: the queue
authors its merge commits with a non-`GITHUB_TOKEN` identity, so workflows
fire normally.

---

## Other recurring CI gotchas

### `pull_request_target` workflows

Workflows that need write access to the repo from a PR (e.g. the Dependabot
lockfile normalizer) use `pull_request_target` so the `GITHUB_TOKEN` carries
write scopes. Two hard rules apply to anything we add to that family:

1. Never run a script defined inside the PR's working tree (`npm run …`,
   `make …` against PR `Makefile`, `tox` against PR `tox.ini`, etc.). A PR
   can redefine those scripts to exfiltrate the privileged token.
2. Always use `--ignore-scripts` (or the equivalent) on package installers so
   transitive postinstall hooks cannot execute either.

`.github/workflows/dependabot-ui-lockfile-normalize.yml` is the canonical
example: it runs `npm install --package-lock-only --ignore-scripts` directly
instead of `npm run lock:normalize`.

### Required checks renamed

If a workflow job is renamed, its old name stays as a required context until
someone updates the branch protection rule. Symptom: every PR is blocked on a
check name that no longer exists. Fix: Settings → Branches → main protection
rule → re-select required contexts.
