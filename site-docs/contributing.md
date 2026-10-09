# Contributing to agent-bom

Thank you for your interest in contributing to **agent-bom**! This project aims to become the industry standard for AI agent and MCP server security, and we welcome contributions from developers, security researchers, and users.

## Code of Conduct

Please read and follow our [Code of Conduct](https://github.com/msaad00/agent-bom/blob/main/CODE_OF_CONDUCT.md). Be respectful, inclusive, and constructive.

## Getting Started

```bash
git clone https://github.com/msaad00/agent-bom.git
cd agent-bom

uv sync --extra dev-all
uv run agent-bom --version
```

## Running Tests

```bash
uv run pytest tests/ -x -q
```

## Code Style

We use `ruff` for linting:

```bash
uv run ruff check src tests
uv run ruff format --check src tests
```

## Areas to Contribute

- **New MCP client configs** — Add discovery paths for new MCP clients (see `discovery/__init__.py`)
- **New package ecosystems** — Add parsers for Ruby (Gemfile.lock), .NET (packages.lock.json), etc.
- **Cloud providers** — Extend AWS/Azure/GCP/Snowflake discovery modules
- **Output formats** — New export targets, dashboard improvements
- **Registry expansion** — Add MCP server entries to `mcp_registry.json`

## Pull Request Process

1. Fork the repo and create your branch from `main`
2. Add tests for any new functionality
3. Ensure all tests pass: `uv run pytest tests/ -x -q`
4. Ensure linting passes: `uv run ruff check src tests`
5. Update the README if needed
6. Submit your PR with a clear description

**Branch protection:** All PRs require 1 approving review from a code owner, 5 CI checks to pass, and signed commits. Admins cannot bypass these rules.

## Version Bump Checklist

Release versions are managed by script, not by hand:

```bash
python scripts/bump-version.py X.Y.Z            # prepare the next source version
python scripts/bump-version.py X.Y.Z --check    # CI drift gate
python scripts/bump-version.py --published X.Y.Z  # only after X.Y.Z is published
```

The script updates the package, chart, Dockerfiles, manifests and docs.
User-facing copy-paste commands track `PUBLISHED_VERSION` so they never point
at a tag that does not exist yet. `make preflight` runs the same drift gates CI
runs.

## Honesty Rule

Only document and claim features that are actually implemented and tested. Do not add stubs, placeholders, or roadmap items as if they are shipping features.

## Developer Certificate of Origin (DCO)

All contributions must include a `Signed-off-by` line in the commit message
(use `git commit -s`). By signing off, you certify that you have the right
to submit the work under this project's license per the
[Developer Certificate of Origin v1.1](https://developercertificate.org/).

## Reporting Security Issues

If you discover a security vulnerability, please use [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories) or email andwgdysaad@gmail.com instead of opening a public issue.
