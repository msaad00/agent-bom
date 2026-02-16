# Contributing to agent-bom

Thank you for your interest in contributing to **agent-bom**! This project aims to become the industry standard for AI agent and MCP server security, and we welcome contributions from developers, security researchers, and users.

## Code of Conduct

Be respectful, inclusive, and constructive. We're building tools to make AI infrastructure more secure - let's keep our community secure too.

## Getting Started

```bash
git clone https://github.com/agent-bom/agent-bom.git
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

- **New MCP client configs** — Add discovery paths for new MCP clients
- **New package ecosystems** — Add parsers for Ruby (Gemfile.lock), .NET (packages.lock.json), etc.
- **Live MCP introspection** — Connect to running servers to enumerate tools/resources
- **Container scanning** — Extract packages from Docker images
- **Output formats** — SPDX 3.0, HTML reports, Markdown
- **Policy engine** — Configurable rules for acceptable risk thresholds

## Pull Request Process

1. Fork the repo and create your branch from `main`
2. Add tests for any new functionality
3. Ensure all tests pass
4. Update the README if needed
5. Submit your PR with a clear description

## Reporting Security Issues

If you discover a security vulnerability, please email andwgdysaad@gmail.com instead of opening a public issue.
