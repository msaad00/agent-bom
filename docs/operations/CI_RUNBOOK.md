# CI Runbook

Operational guidance for the agent-bom CI pipeline. Use this when a PR is
stuck, a workflow fails unexpectedly, or you need to retrigger checks.

---

## CI lanes

PR CI runs the full correctness and live Postgres integration suites on GitHub's merge result, alongside
changed-domain tests and contract smoke. The selected tests provide early
feedback; they do not replace the required full suite. Deployment and performance
lanes also run on `main` and nightly. All lanes live in `ci.yml` unless noted.

| Lane | Pull request | Push to `main` | Nightly / manual |
|---|---|---|---|
| Lint and Type Check (ruff, mypy with main-seeded cache) | yes (required) | yes | yes |
| Security Scan (policy gates, bandit, OSV, npm advisories, release call-graph lint) | yes (required) | yes | yes |
| Build Package (wheel + clean-venv MCP smoke) | yes (required, starts immediately) | yes | yes |
| Test (Python 3.13): full correctness + changed-domain and cross-surface contracts | yes (required) | yes | yes |
| Version Alignment (drift, counts, OpenAPI, schemas) | yes | yes | yes |
| CodeQL (Python excluding `tests/`, Actions) | yes (required) | yes | weekly |
| PR Security Gate (pip-audit, self-scan), Dependency Review, Gitleaks | yes | yes (except Dependency Review) | - |
| UI Validate (lint, vitest, schema drift) + UI export build | when UI inputs change | when UI inputs change | yes |
| Docs Strict, Helm, Compose, Endpoint packaging | when their inputs change | when their inputs change | yes |
| Native App image and persistence | when its inputs change | yes | yes |
| Full correctness suite, Python 3.11/3.12/3.13/3.14 (3.11 with coverage floor) | yes (required through aggregation) | yes | yes |
| Graph performance, Output scale performance, Extra-gated SDK smoke | no | yes | yes |
| Postgres Integration Contract (live RLS, migrations, schema parity) | yes (required through aggregation) | yes | yes |
| Test (Alpine/musl) | no | subset; full on dependency changes | full suite nightly, subset manual |
| Docker (multi-arch) + image scans | no | yes | nightly only |
| UI E2E and container smoke (Playwright, bundle budget) | no | when UI inputs change | yes |
| Dogfood GitHub Action | no | when action inputs change | yes |
| ClusterFuzzLite (`cflite-pr.yml`) | no | short batch on parser changes | weekly long batch |
| Runtime Helm Acceptance (`runtime-acceptance.yml`) | only gateway/runtime changes | API/Helm/Postgres/UI-gateway changes | manual |

Why a release is still safe: `release.yml` runs
`scripts/check_release_main_ci.py`, which accepts a tag only when the exact
`main` HEAD has a completed, successful `ci.yml` **push** run. On push (and on
nightly, merge-queue, and manual runs), `Python correctness aggregation`
treats a skipped post-merge lane as a failure, and `Test (Python 3.13)`
requires the Docker lane, so a green `main` run means the full suite, the
performance/Postgres lanes, and the release image all passed. Superseded PR
runs are cancelled; each `main` SHA has its own concurrency group so neither
running nor pending evidence is superseded by another main commit. Verify the
exact SHA instead of treating an older run as release proof.
A post-merge regression opens a
`ci-regression` issue through `main-failure-alert.yml`, which watches
`CI/CD Pipeline`, `Runtime Helm Acceptance`, and `ClusterFuzzLite`.

When required main checks fail, freeze further merges and releases. Repair the
failure through a reviewed change and verify that exact merged SHA before
resuming. Do not automatically revert or tag over missing or failing evidence.

---

## Documentation-only fast path

The CI path classifier treats a change as documentation-only only when every
changed path is a recognized public documentation file or asset. Empty,
mixed, malformed, workflow, dependency, source, UI, and deployment path sets
fail closed to the normal validation lanes.

For a documentation-only pull request, the five branch-protection contexts
still attach to the head SHA. The full correctness suite remains mandatory.
Selected smoke, dependency scanning, type checking and package construction
use explicit fast-success steps instead of disappearing
through workflow-level path filters. Public-doc hygiene, release-copy/count
consistency, strict MkDocs validation when applicable, and the unconditional
gitleaks range scan still run. Main pushes use the same classification; merge
queues, manual runs, classifier failures, and workflow changes run the full
lanes.

The dependency-focused PR security workflow uses the same classifier. CodeQL
and gitleaks remain independent, always-triggered controls so this optimization
does not weaken branch-protection or secret-scanning behavior.

---

## Inspect current protection first

As verified on October 6, 2026, legacy `main` protection uses
`required_status_checks.strict = true` and these five contexts:
`Lint and Type Check`, `Test (Python 3.13)`, `Build Package`, `Security Scan`,
and `CodeQL`. The branch rules endpoint returned no active ruleset rules.
These are a dated settings snapshot, not configuration enforced by this file.
Recheck before diagnosing a blocked merge:

```sh
gh api repos/msaad00/agent-bom/branches/main/protection/required_status_checks \
  --jq '{strict, contexts}'
gh api repos/msaad00/agent-bom/rules/branches/main --jq '[.[] | .type] | unique'
gh pr view <PR_NUMBER> --json headRefOid,reviewDecision,mergeStateStatus,statusCheckRollup
```

Strict protection requires validation against current main. Review, signature,
missing-context and other rules can also block merging. Do not weaken protection
to compensate for missing CI evidence.

Security changes and large diffs require an independent written review before
merge. The reviewer records the head SHA, material correctness and security
findings, verification considered, and any unresolved risks. A bare approval
does not satisfy this review policy. GitHub's approval count does not validate
the review's contents; the merge operator must check that evidence explicitly.

## Ready PRs blocked behind `main`

### Symptom

A PR is approved, auto-merge is enabled, and all current checks are green, but
GitHub still says **This branch is out-of-date with the base branch** or
**branch update already in progress**. This becomes common when several small
readiness PRs are stacked behind a strict `main` branch protection rule.

### Root cause

If live protection reports `required_status_checks.strict = true`, advancing
`main` can require a refreshed PR head. When a refresh is needed, follow
the signed local-rebase workflow in `AGENTS.md`, revalidate, and push once with
`--force-with-lease`. Let the new head's checks finish.

### Available recovery automation

`.github/workflows/auto-retrigger-stranded.yml` now runs on PR synchronize
events, every push to `main`, on a 15-minute schedule, and on manual dispatch.
It first runs:

```sh
scripts/refresh_ready_prs.sh
```

The script only refreshes same-repo, non-draft PRs targeting `main`. By default
it further limits writes to PRs with auto-merge already enabled, so exploratory
branches are left alone. Branch refresh and close/reopen retrigger require
`AUTOMATION_GITHUB_TOKEN`, a dedicated GitHub App token or PAT with repo
pull-request/write access. Do not use `GITHUB_TOKEN` for refresh or
close/reopen recovery when unattended CI is required: GitHub token-authored
PR events can require manual workflow approval. Verify the current-head runs
and approval banner before deciding that a workflow is missing.

If `AUTOMATION_GITHUB_TOKEN` is not configured, the workflow now uses a
lower-privilege fallback:

```sh
scripts/dispatch_required_ci.sh <PR_NUMBER>
```

That fallback dispatches the required PR workflows (`ci.yml`,
`pr-security-gate.yml`, and, when needed, `codeql.yml`) through
`workflow_dispatch` for same-repo PR heads that already contain current `main`.
It cannot update stale branches, but it prevents the common "all visible checks
passed, required contexts are still expected" state from wasting a merge cycle.

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

Inspect the event, token identity, queued runs, and approval state. An empty
check list does not by itself prove that GitHub suppressed an event. Current
GitHub documentation says `GITHUB_TOKEN`-authored `opened`, `synchronize`, and
`reopened` PR events create approval-required runs; ordinary token-authored
pushes do not start push workflows. Dispatch events are explicit exceptions.
A UI branch update is not automatically evidence of a `GITHUB_TOKEN` actor.

See [GitHub's token event behavior](https://docs.github.com/en/actions/concepts/security/github_token#when-github_token-triggers-workflow-runs).
Check the exact head even when `strict=false`: required contexts still need
valid evidence for that head.

### Fix the stranded PR (one-shot)

```sh
scripts/retrigger_stranded_pr.sh <PR_NUMBER>
```

The script:

1. Resolves the PR's current head SHA.
2. Checks the five branch-protection contexts (`Lint and Type Check`, Python
   3.13, package build, security scan, and CodeQL) against that SHA via
   `repos/.../commits/<sha>/check-runs`.
3. Cancels required-workflow runs for older SHAs on the exact PR branch. If a
   normal cancellation does not finish within a short grace, it uses GitHub's
   force-cancel endpoint; current-head and unrelated runs are never targeted.
4. If any current-head required check is still active, exits without
   retriggering. Downstream jobs such as package build are not created until
   prerequisite jobs finish.
5. If checks are missing or stale after the run is idle, closes the PR and
   immediately reopens it. Use a dedicated App token or PAT for unattended
   recovery; token-authored PR events may otherwise require approval.

The script no-ops when the required check is already present, so it is safe to
run on any PR.

### Event-driven auto-retrigger

`.github/workflows/auto-retrigger-stranded.yml` runs `scripts/retrigger_stranded_pr.sh`
against every synchronized PR whose current head SHA has zero or stale
required checks. It runs immediately after a PR push, after `main`
advances, every 15 minutes, and through `workflow_dispatch` for on-demand. Once this workflow is on the
default branch and `AUTOMATION_GITHUB_TOKEN` is configured, eligible stranded
PRs can recover automatically. The fallback schedule is every 15 minutes and
GitHub may delay it; there is no five-minute recovery guarantee.

When the automation token is absent, the workflow falls back to
`scripts/dispatch_required_ci.sh` and dispatches required workflows for current
same-repo PR heads. This is less powerful than branch refresh, but it is enough
for PRs that are already rebased and only missing required status contexts.

Operator-side troubleshooting if a strand persists past ~10 minutes:

- Did the workflow itself run? `gh run list --workflow=auto-retrigger-stranded.yml --limit 5`
- Is `AUTOMATION_GITHUB_TOKEN` configured? Without it the workflow can dispatch
  required checks for current heads, but cannot refresh stale branches or use
  the close/reopen retrigger path.
- Was the PR younger than `MIN_AGE_MINUTES` (3 min by default)? It's intentionally
  skipped to give the initial `pull_request` workflow a chance to start.
- Did `gh api commits/{sha}/check-runs` return zero, or did branch protection
  change? Keep `REQUIRED_CHECKS` aligned with the protected contexts.

### Optional merge-queue configuration

Merge queue is a separate owner-controlled settings decision. The three
required-check workflows (`ci.yml`, `codeql.yml`, `pr-security-gate.yml`)
declare `merge_group: types: [checks_requested]`; this proves trigger support,
not that a queue is enabled or available for the repository's plan.

Use `scripts/enable_merge_queue.sh --check` for read-only inspection. If the
owner enables a supported queue, copy the five live required contexts from
the API output above and verify a real merge-group run. Do not configure the
four full-correctness matrix job names as separate required contexts: the stable
`Test (Python 3.13)` aggregation already requires all of them. Keep strict
protection when a queue is unavailable and retain the exact-main release gate.

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
