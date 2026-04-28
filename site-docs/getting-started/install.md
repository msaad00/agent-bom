# Installation

## pip / pipx (recommended)

```bash
pip install agent-bom
# or
pipx install agent-bom
```

## With optional extras

```bash
pip install "agent-bom[api]"         # REST API server
pip install "agent-bom[mcp-server]"  # MCP server dependencies
pip install "agent-bom[dashboard]"   # Streamlit dashboard
pip install "agent-bom[all]"         # Everything
```

## Docker

```bash
# CLI scanning
docker run --rm ghcr.io/msaad00/agent-bom:latest scan

# With host config access (for MCP client discovery)
docker run --rm \
  -v "$HOME/.config:/home/abom/.config:ro" \
  -v "$HOME/Library/Application Support:/home/abom/Library/Application Support:ro" \
  ghcr.io/msaad00/agent-bom:latest scan
```

## From source

```bash
git clone https://github.com/msaad00/agent-bom.git
cd agent-bom
pip install -e ".[dev]"
```

## Verify installation

```bash
agent-bom --version
agent-bom scan --help
```

## Requirements

- Python 3.11+
- Optional: Docker (for container image scanning)
- Optional: kubectl (for Kubernetes scanning)
- Optional: semgrep (for SAST code scanning)
- No external API keys required for basic operation
