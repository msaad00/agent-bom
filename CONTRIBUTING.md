# Contributing to agent-bom

Thank you for your interest in contributing to **agent-bom**! This project aims to become the industry standard for AI agent and MCP server security, and we welcome contributions from developers, security researchers, and users.

## Code of Conduct

Please read and follow our [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Be respectful, inclusive, and constructive.

## Getting Started

```bash
git clone https://github.com/msaad00/agent-bom.git
cd agent-bom

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"
```

## Running Tests

```bash
pytest tests/ -v
```

## Code Style

We use `ruff` for linting:

```bash
ruff check src/
ruff format src/
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
3. Ensure all tests pass: `pytest tests/ -x -q`
4. Ensure linting passes: `ruff check src/`
5. Update the README if needed
6. Submit your PR with a clear description

**Branch protection:** All PRs require 1 approving review from a code owner, 5 CI checks to pass, and signed commits. Admins cannot bypass these rules.

## Version Bump Checklist

When preparing a release, update the version in all of these files:

1. `pyproject.toml` — `version = "X.Y.Z"`
2. `src/agent_bom/__init__.py` — `__version__ = "X.Y.Z"`
3. `Dockerfile` — version label
4. `Dockerfile.sse` — `ARG VERSION=X.Y.Z`
5. `integrations/mcp-registry/server.json` — `version`
6. `integrations/openclaw/SKILL.md` — version in frontmatter
7. `action.yml` — version in description + branding
8. `README.md` — version references in examples
9. `PUBLISHING.md` — version references
10. `tests/test_version.py` — expected version string

## Honesty Rule

Only document and claim features that are actually implemented and tested. Do not add stubs, placeholders, or roadmap items as if they are shipping features.

## Reporting Security Issues

If you discover a security vulnerability, please use [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories) or email andwgdysaad@gmail.com instead of opening a public issue.
