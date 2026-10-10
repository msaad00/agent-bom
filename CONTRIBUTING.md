# Contributing to agent-bom

agent-bom runs against real AI agent deployments, so every contribution directly improves security for the people relying on it. This guide gets you from zero to merged PR.

Not contributing code, just need help? [SUPPORT.md](SUPPORT.md) has the routing
and what response to expect.

The best ways to help:

- Try the demo and open issues for confusing output, missing context, or weak remediation.
- Request integrations for MCP clients, coding agents, CI systems, cloud providers, and security workflows you actually use.
- Pick a `good first issue` or `help wanted` task and comment before starting.
- Improve docs, screenshots, diagrams, and first-run examples when something is unclear.
- Star, share, or recommend the project when agent-bom gives you useful evidence; community signal helps security teams trust an open tool.

## Table of contents

- [Your first PR in 30 minutes](#your-first-pr-in-30-minutes)
- [What to work on](#what-to-work-on)
- [Development workflow](#development-workflow)
- [Tests](#tests)
- [Code style](#code-style)
- [Dependency updates](#dependency-updates)
- [Submitting a PR](#submitting-a-pr)
- [What to expect from maintainers](#what-to-expect-from-maintainers)
- [Architecture overview](#architecture-overview)
- [Security reports](#security-reports)

---

## Your first PR in 30 minutes

You do not need to understand the whole codebase to land a useful change. This
path keeps the loop small.

**1. Set up (about 5 minutes).** You need Python 3.11+ and
[uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/msaad00/agent-bom.git
cd agent-bom
uv sync --extra dev                  # core workflow; use --extra dev-all for the full suite
uv run pre-commit install            # ruff + ruff-format on every commit
uv run agent-bom scan --demo --offline
```

**2. Find where your change goes (about 5 minutes).** Open
[`docs/CODE_MAP.md`](docs/CODE_MAP.md). It maps "I want to add X" to the
subpackage that owns it. New Python files go in a subpackage, not directly
under `src/agent_bom/`.

**3. Run a narrow test, not the whole suite (about 5 minutes).** List the tests
related to the files you changed, then run only those:

```bash
python scripts/pytest_ci_plan.py targeted src/agent_bom/parsers/python_parsers.py
uv run pytest tests/test_manifest_parser_coverage.py -q   # one file from that list
```

**4. Run the checks that catch most review comments (about 5 minutes).**

```bash
uv run ruff check src tests && uv run ruff format --check src tests
python scripts/check_package_layout.py   # no new top-level modules
python scripts/check_architecture.py     # layer rules and size/complexity ratchet
make preflight                           # only if you touched api/ routes or models
```

**5. Open the PR (about 10 minutes).** Use a conventional title
(`fix(parsers): ...`), fill in the template, list the commands you ran, and sign
off your commit (`git commit -s`). Draft PRs are welcome if you want early
feedback on direction.

**How CI gates work.** A change classifier runs first. Docs-only PRs skip the
Python test shards, while code PRs run lint, mypy, the architecture and
package-layout checks, sharded pytest and the Docker build. A red check names
the script or test that failed, and you can run the same script locally. If a
check says "The operation was canceled", a newer push superseded it. Re-run it
instead of debugging.

**Where to ask.** Ask placement or design questions in your issue or draft PR,
open-ended ones in
[GitHub Discussions](https://github.com/msaad00/agent-bom/discussions), and
quick PR questions in `#contributors` on
[Discord](https://discord.gg/3YmYPqKZh5).

---

## What to work on

### Easiest — good first issues

Browse [`good first issue`](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3A%22good+first+issue%22) on GitHub. No architecture knowledge required.

**That queue is often empty.** Labelled starter issues get opened in batches and
picked up quickly, so an empty result is normal and does not mean the project is
closed to contributions. When it is empty, take one of the standing tasks below,
or open an issue proposing what you want to do — describing it first is welcome
and saves you writing the wrong thing.

### Good first contribution areas

| Area | Where | Shape of a good first PR |
|---|---|---|
| Scanner importers | `src/agent_bom/parsers/external_scanners.py` | Map one more field or format from another tool's JSON/SARIF, with a fixture-based test |
| IaC rules | `src/agent_bom/iac/` | One new Dockerfile, Kubernetes, Terraform or CloudFormation rule, with a passing and a failing fixture |
| CSPM checks | `src/agent_bom/cloud/aws_cis/`, `azure_cis/`, `gcp_cis/` | One benchmark control, tested against mocked API responses |
| MCP registry entries | `src/agent_bom/mcp_registry.json` | One server entry (see below) |
| Docs fixes | `docs/`, `site-docs/` | Fix a stale command, path or link you tripped over |
| UI | `ui/` | A small, screenshot-verified fix in light and dark themes |

Typical good-first tasks:
- **Add an MCP client** — add an `AgentType` member in [`src/agent_bom/models.py`](src/agent_bom/models.py), its per-platform config paths to `CONFIG_LOCATIONS` in [`src/agent_bom/discovery/__init__.py`](src/agent_bom/discovery/__init__.py), and a display label to `_DISPLAY_NAMES` in [`src/agent_bom/discovery/coverage.py`](src/agent_bom/discovery/coverage.py). A `CONFIG_LOCATIONS` entry maps the agent type to `{"Darwin": [...], "Linux": [...], "Windows": [...]}`; clients whose config is not JSON are dispatched by an explicit branch in `discover_global_configs`, not by a field on the entry.
- **Add a registry entry** — add a server object to [`src/agent_bom/mcp_registry.json`](src/agent_bom/mcp_registry.json), following the shape of its neighbours. Bump the `_total_servers` header to match: `tests/test_stats_alignment.py` asserts the two agree, so a new entry fails CI without it.
- **Fix a stale doc reference** — several docs cite files that have moved or no longer exist. `grep` a path out of a `docs/**/*.md` table, confirm it resolves, and correct it where it does not.
- **Improve a docstring** — any function in `src/agent_bom/` without a clear docstring. `src/agent_bom/repo_auto_detect.py` is a good place to start: the `project_has_*` predicates are undocumented except `project_has_iac`, which shows the format to copy.

### Medium — help wanted

Browse [`help wanted`](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3A%22help+wanted%22).

Typical help-wanted tasks:
- **A package ecosystem we do not parse yet** — check [`src/agent_bom/parsers/`](src/agent_bom/parsers/) first. Python, npm, Ruby, .NET, Swift, Go, Rust, PHP and others already ship; propose the gap you actually hit.
- **A cloud CIS benchmark we do not cover** — AWS, GCP, Azure and Snowflake modules already exist in [`src/agent_bom/cloud/`](src/agent_bom/cloud/); a new provider follows their pattern.
- **Dashboard improvements** — Next.js components in `ui/` (TypeScript, Tailwind)
- **A new `--format` target** — the current list is `SCAN_OUTPUT_FORMATS` in [`src/agent_bom/cli/options_sources.py`](src/agent_bom/cli/options_sources.py); implementations live in [`src/agent_bom/output/`](src/agent_bom/output/).

Before starting any of these, confirm the gap is still open against the current
tree. This list is periodically overtaken by shipped work.

### Critical — P0 issues

See [open issues labeled P0](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3AP0) for the most impactful work. These close core coverage gaps (OS-level scanning, container image analysis, CWE enrichment, IaC misconfiguration, compliance frameworks). Comment on the issue before starting — these require coordination.

### Priority — P1 features

See [open issues labeled P1](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3AP1) for high-impact work that's well-scoped and ready to pick up.

---

## Development workflow

Start with [`AGENTS.md`](AGENTS.md) when using assistant or agent workflows in
this repo. It captures the product, security, verification, and release lenses
that should be applied alongside this contributor guide.

```bash
# Create a branch
git checkout -b feat/your-feature   # or fix/your-fix

# Make your changes, then run:
uv run ruff check src tests --fix   # lint + autofix
uv run ruff format src tests        # formatting
uv run pytest tests/ -x -q          # full suite must stay green

# Pre-commit hooks do this automatically on commit
git add -p                          # stage intentionally
git commit -m "feat: your message"
gh pr create --base main            # or push + open PR on GitHub
```

Branch naming: `feat/`, `fix/`, `docs/`, `chore/` prefixes. Always branch from and PR to `main`.

### Important PR update rule

Do **not** use GitHub's **Update branch** button on active PRs unless the PR is
actually non-mergeable and you cannot refresh it locally.

If GitHub only says **"This branch is out-of-date with the base branch"**, that
does **not** automatically mean there is a conflict. In this repo, that banner
is informational unless merge protection explicitly blocks on being current with
`main`.

Preferred path:

```bash
scripts/refresh-pr-branch.sh your-branch
```

Why:

- GitHub's synthetic merge head can leave PRs in a bad check state where
  expected checks never attach cleanly
- a real locally pushed head is more reliable for CI, branch protection, and
  debugging

If a PR ever shows "no checks reported", "expected" checks with no attached
run, or obviously stale check-rollup state after an update, replace the branch
head with a clean local rebase instead of retrying the GitHub button again.

Manual equivalent:

```bash
git fetch origin
git checkout your-branch
git rebase origin/main
git push --force-with-lease origin your-branch
```

---

## Tests

```bash
uv run pytest tests/ -x -q          # all tests, stop on first fail
uv run pytest tests/ -k "scanner" -v
uv run pytest tests/test_core.py -v
```

**Rules:**
- Every new feature needs at least one test.
- Every bug fix needs a **regression test** that fails without the fix and passes with it. This is enforced during code review — PRs that fix bugs without a regression test will be asked to add one. Over 90% of historical `fix:` commits include regression tests.
- Network tests (hitting real APIs) are marked `@pytest.mark.network` and skipped in CI. Use mocks for unit tests.
- The test suite must stay green. Pre-existing failures are bugs, not technical debt.
- **Coverage floor:** CI enforces a minimum statement coverage threshold (currently 73%, target 80% per [#529](https://github.com/msaad00/agent-bom/issues/529)). PRs that drop coverage below the floor will fail CI.

**Test layout:**

| Directory | What it tests |
|-----------|--------------|
| `tests/test_core.py` | CLI commands, report generation |
| `tests/test_scanner_ecosystems.py` | OSV ecosystem mapping |
| `tests/test_nvidia_advisory.py` | NVIDIA CSAF advisory enrichment |
| `tests/test_accuracy_baseline.py` | Known-vuln packages always detected (network) |
| `tests/test_runtime_*.py` | Proxy, detectors, patterns |
| `tests/test_api_*.py` | REST API endpoints |

---

## Code style

- **Formatter:** `ruff format` (Black-compatible, line length 120)
- **Linter:** `ruff check` — all rules in `pyproject.toml`
- **Types:** Type hints on all new public functions. `mypy` is run in CI.
- **No `print()`** — use `console.print()` (Rich) in CLI code, `logging` in library code.
- **No stubs or vaporware** — only document and claim features that are implemented and tested.
- **Shell scripts:** every script must enable strict mode at the top. Bash scripts (`#!/usr/bin/env bash` or `#!/bin/bash`) must use `set -euo pipefail`. POSIX `sh` scripts (`#!/bin/sh`) must use `set -eu` — `pipefail` is a non-POSIX extension and is intentionally omitted on `sh` shebangs to keep endpoint installers (Jamf, Kandji, Alpine `ash`) portable.

Pre-commit hooks enforce ruff on every commit. Install once with `pre-commit install`.

---

## Dependency updates

Dependency updates are part of the shipped product surface, not background noise.

**Review bar**
- Patch and minor updates still need green CI, security scan, and release-surface alignment.
- Major updates need a short human review of upstream release notes before merge.
- If an update changes user-visible behavior, contracts, runtime assumptions, or packaging, call that out in the PR body and release notes where applicable.
- Do not merge “green but unexplained” upgrades. We should be able to say what changed, why it is safe, and what we validated.

**For Dependabot and manual upgrade PRs include**
- the package and version change
- whether it is patch, minor, or major
- any breaking-change risk or notable upstream release-note items
- what was validated locally or in CI
- whether docs, examples, pins, or release-managed files also needed updating

This keeps update history readable for operators and makes package maintenance look intentional rather than accidental.

---

## Submitting a PR

1. **Branch from main** and name it `feat/`, `fix/`, `docs/`, or `chore/`.
2. **All tests pass:** `uv run pytest tests/ -x -q`
3. **Lint clean:** `uv run ruff check src tests && uv run ruff format --check src tests`
4. **PR description:** one-sentence summary, what changed, how to test it. If the PR resolves a GitHub issue, include `Closes #<issue-number>` in the PR body — GitHub will auto-close the issue when the PR merges.
5. **One review required** — see [what to expect](#what-to-expect-from-maintainers).

By submitting a pull request, you certify that your contribution is made under the terms of the Apache-2.0 license and that you have the right to submit it under those terms (Developer Certificate of Origin).

CI checks that run on every PR:
- `pytest` (sharded; docs-only PRs skip it)
- `ruff check` + `ruff format --check`
- `mypy` type check
- Architecture and package-layout checks (`scripts/check_architecture.py`, `scripts/check_package_layout.py`)
- Version alignment (all version strings must match)
- Docker build

**Commit style:** `type: short description` — types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`.

For dependency PRs, prefer a one-line summary in the body such as:

```md
Upgrade type: minor
Release notes reviewed: yes
Breaking changes expected: no
Validation: CI + targeted local tests
```

---

## What to expect from maintainers

The project is maintained by a small team, so these are goals rather than an
SLA (see [SUPPORT.md](SUPPORT.md)):

- **First response on a PR or a "can I take this?" comment:** we aim for
  within a few days. Around releases it can take longer.
- **Review:** concrete and actionable. If a change belongs in a different
  package or needs a smaller scope, we say so early rather than after several
  rounds.
- **Stalled PRs:** if you go quiet for a few weeks, a maintainer may finish
  the PR, keeping your commits and credit, or close it with a note. You can
  always reopen it.
- **Scope we usually decline:** new top-level modules, new deployment targets
  without an owner, and large refactors without a prior issue. Opening an issue
  first saves you time.

---

## Architecture overview

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system diagrams and [docs/CODE_MAP.md](docs/CODE_MAP.md) for where new code goes.

**One product, shared evidence:** scanning, the self-hosted control plane, and
runtime enforcement share inventory, findings, graph and audit contracts.
The `agent-bom`, `agent-shield`, `agent-cloud`, `agent-iac` and `agent-claw`
commands are focused entry points into the same package.

Pipeline at a glance: **discover** MCP configs → **parse** packages → **scan** via OSV/NVD/GHSA → **enrich** (EPSS + KEV) → **blast radius** → **compliance tag** → **output**.

---

## Honesty rule

Only document and claim features that are actually implemented and tested. Do not add stubs, placeholders, or roadmap items as shipping features.

---

## Version bump

Use `scripts/bump-version.py`. It updates the release-managed version surfaces in one go. See `docs/PUBLISHING.md` for the full release checklist.

---

## Developer Certificate of Origin

All contributions must include a `Signed-off-by` line (`git commit -s`). By signing, you certify you have the right to submit the work under the Apache 2.0 license per [DCO v1.1](https://developercertificate.org/).

---

## Security reports

Please **do not open a public issue** for security vulnerabilities. Use [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories) or email andwgdysaad@gmail.com. We aim to respond within 48 hours.
