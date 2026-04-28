# CI Runbook

Operational guidance for the agent-bom CI pipeline. Use this when a PR is
stuck, a workflow fails unexpectedly, or you need to retrigger checks.

---

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
3. If not, closes the PR and immediately reopens it. The `pull_request
   reopened` event always fires `pull_request` workflows, so all required
   checks restart on the up-to-date head.

The script no-ops when the required check is already present, so it is safe to
run on any PR.

### Permanent fix options (settings change required)

Pick one — none of these can be enabled from a workflow file alone.

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

#### How to flip it

The merge queue cannot be enabled via the legacy `branches/{branch}/protection`
REST endpoint. Use the **repository rulesets** API (or the Settings UI). The
helper script wraps the API call:

```sh
# preview the payload (no changes made)
scripts/enable_merge_queue.sh --dry-run

# enable on main (requires admin token; one-time)
GH_TOKEN=<admin-pat> scripts/enable_merge_queue.sh
```

If you prefer the UI: **Settings → Branches → main → Edit rule →** check
"Require merge queue", set the same status-check list as today, save. Confirm
with `gh api repos/<owner>/<repo>/branches/main/protection --jq .required_status_checks`.

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
