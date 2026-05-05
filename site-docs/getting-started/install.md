# Installation

## pip / pipx (recommended)

```bash
pip install agent-bom
# or
pipx install agent-bom
```

## With optional extras

```bash
pip install "agent-bom[api]"          # REST API server
pip install "agent-bom[ui]"           # API plus bundled local UI support
pip install "agent-bom[mcp-server]"   # MCP server dependencies
pip install "agent-bom[postgres]"     # Postgres-backed control-plane state
pip install "agent-bom[cloud]"        # AWS, Azure, GCP, Databricks, Snowflake, Nebius, HuggingFace, W&B, OpenAI
pip install "agent-bom[visual]"       # OCR-backed visual-leak detection; also requires Tesseract on PATH
pip install "agent-bom[dashboard]"    # Snowflake Streamlit compatibility dashboard
pip install "agent-bom[dev-all]"      # Developer environment used by this repo
```

Other supported extras in `pyproject.toml` include `otel`, `aws`, `azure`,
`gcp`, `coreweave`, `databricks`, `snowflake`, `nebius`, `huggingface`,
`wandb`, `openai`, `ai-enrich`, `graph`, `pdf`, `watch`, `runtime`, `snyk`,
`oidc`, `saml`, `docs`, and `dev`. There is no `agent-bom[all]` extra.

## Docker

```bash
# CLI scanning
docker run --rm agentbom/agent-bom:latest agents

# With host config access (for MCP client discovery)
docker run --rm \
  -v "$HOME/.config:/home/abom/.config:ro" \
  -v "$HOME/Library/Application Support:/home/abom/Library/Application Support:ro" \
  agentbom/agent-bom:latest agents
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
agent-bom agents --help
```

## Requirements

- Python 3.11+
- Optional: Docker (for container image scanning)
- Optional: kubectl (for Kubernetes scanning)
- Optional: semgrep (for SAST code scanning)
- No external API keys required for basic operation
