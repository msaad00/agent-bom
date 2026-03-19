# Contributing to agent-bom

agent-bom has 7,000+ monthly installs. Every contribution directly improves security for real AI agent deployments. This guide gets you from zero to merged PR.

## Table of contents

- [Quick start (5 minutes)](#quick-start)
- [What to work on](#what-to-work-on)
- [Development workflow](#development-workflow)
- [Tests](#tests)
- [Code style](#code-style)
- [Submitting a PR](#submitting-a-pr)
- [Architecture overview](#architecture-overview)
- [Security reports](#security-reports)

---

## Quick start

```bash
git clone https://github.com/msaad00/agent-bom.git
cd agent-bom
python3 -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install                                  # wires ruff + ruff-format hooks
pytest tests/ -x -q                                # must be green before you start
```

That's it. `agent-bom scan` now runs from your local checkout.

---

## What to work on

### Easiest — good first issues

Browse [`good first issue`](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3A%22good+first+issue%22) on GitHub. No architecture knowledge required.

Typical good-first tasks:
- **Add an MCP client** — 5–15 lines in [`src/agent_bom/discovery/__init__.py`](src/agent_bom/discovery/__init__.py). Each entry is a dict with a config path and parser.
- **Add a registry entry** — Add a JSON object to `mcp_registry.json` (schema in `config/schemas/`).
- **Fix a test** — search for `# TODO` or `pytest.mark.skip` in `tests/`.
- **Improve a docstring** — Any function in `src/agent_bom/` without a clear docstring.

### Medium — help wanted

Browse [`help wanted`](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3A%22help+wanted%22).

Typical help-wanted tasks:
- **New package ecosystem parsers** — Ruby Gemfile.lock, .NET packages.lock.json, Swift Package.resolved
- **Cloud CIS benchmark** — GCP or Azure module following the pattern in `src/agent_bom/cloud/`
- **Dashboard improvements** — Next.js components in `ui/` (TypeScript, Tailwind)
- **Output format** — New `--format` target (CSV, Markdown table, etc.) in `src/agent_bom/output/`

### Critical — P0 issues

See [open issues labeled P0](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3AP0) for the most impactful work. These close core coverage gaps (OS-level scanning, container image analysis, CWE enrichment, IaC misconfiguration, compliance frameworks). Comment on the issue before starting — these require coordination.

### Priority — P1 features

See [open issues labeled P1](https://github.com/msaad00/agent-bom/issues?q=is%3Aopen+label%3AP1) for high-impact work that's well-scoped and ready to pick up.

---

## Development workflow

```bash
# Create a branch
git checkout -b feat/your-feature   # or fix/your-fix

# Make your changes, then run:
ruff check src/ --fix               # lint + autofix
ruff format src/                    # formatting
pytest tests/ -x -q                 # full suite must stay green

# Pre-commit hooks do this automatically on commit
git add -p                          # stage intentionally
git commit -m "feat: your message"
gh pr create --base main            # or push + open PR on GitHub
```

Branch naming: `feat/`, `fix/`, `docs/`, `chore/` prefixes. Always branch from and PR to `main`.

---

## Tests

```bash
pytest tests/ -x -q                 # all tests, stop on first fail
pytest tests/ -k "scanner" -v       # run matching tests only
pytest tests/test_core.py -v        # specific file
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

Pre-commit hooks enforce ruff on every commit. Install once with `pre-commit install`.

---

## Submitting a PR

1. **Branch from main** and name it `feat/`, `fix/`, `docs/`, or `chore/`.
2. **All tests pass:** `pytest tests/ -x -q`
3. **Lint clean:** `ruff check src/ && ruff format --check src/`
4. **PR description:** one-sentence summary, what changed, how to test it. If the PR resolves a GitHub issue, include `Closes #<issue-number>` in the PR body — GitHub will auto-close the issue when the PR merges.
5. **One review required** — a maintainer will review within a few days.

By submitting a pull request, you certify that your contribution is made under the terms of the Apache-2.0 license and that you have the right to submit it under those terms (Developer Certificate of Origin).

CI checks that run on every PR:
- `pytest` (all tests)
- `ruff check` + `ruff format --check`
- `mypy` type check
- Version alignment (all version strings must match)
- Docker build

**Commit style:** `type: short description` — types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`.

---

## Architecture overview

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for system diagrams and the full module map.

**5 products, 1 package:** `agent-bom` (BOM + scanning), `agent-shield` (runtime protection), `agent-cloud` (cloud posture), `agent-iac` (IaC security), `agent-claw` (fleet governance). All share the same core engine.

Pipeline at a glance: **discover** MCP configs → **parse** packages → **scan** via OSV/NVD/GHSA → **enrich** (EPSS + KEV) → **blast radius** → **compliance tag** (14 frameworks) → **output** (16 formats).

---

## Honesty rule

Only document and claim features that are actually implemented and tested. Do not add stubs, placeholders, or roadmap items as shipping features.

---

## Version bump

Use `scripts/bump-version.py`. It updates all 19 files in one go. See `docs/PUBLISHING.md` for the full release checklist.

---

## Developer Certificate of Origin

All contributions must include a `Signed-off-by` line (`git commit -s`). By signing, you certify you have the right to submit the work under the Apache 2.0 license per [DCO v1.1](https://developercertificate.org/).

---

## Security reports

Please **do not open a public issue** for security vulnerabilities. Use [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories) or email andwgdysaad@gmail.com. We aim to respond within 48 hours.
