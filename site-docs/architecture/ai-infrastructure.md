# AI Infrastructure Scanning

For the comprehensive guide, see [AI_INFRASTRUCTURE_SCANNING.md](https://github.com/msaad00/agent-bom/blob/main/docs/AI_INFRASTRUCTURE_SCANNING.md).

## Supported infrastructure

| Layer | What we scan |
|-------|-------------|
| **MCP Clients** | 21 clients — Claude, Cursor, VS Code, Windsurf, Cline, Codex, Gemini, Goose, etc. |
| **MCP Servers** | Package deps, tool definitions, credential exposure, description drift |
| **Container Images** | OS + language packages via Grype/Syft |
| **Kubernetes** | Namespace enumeration, pod MCP detection |
| **Cloud** | AWS, Snowflake, Azure ML, GCP Vertex AI, Databricks, HuggingFace, Ollama |
| **Code** | SAST via Semgrep with CWE mapping |

## Cloud providers

| Provider | Module | CIS Benchmark |
|----------|--------|---------------|
| AWS | `cloud/aws.py` | CIS AWS Foundations v3.0 |
| Snowflake | `cloud/snowflake.py` | CIS Snowflake v1.0 |
| Azure | `cloud/azure.py` | — |
| GCP | `cloud/gcp.py` | — |
| Databricks | `cloud/databricks.py` | — |
| HuggingFace | `cloud/huggingface.py` | — |
| Ollama | `cloud/ollama.py` | — |
