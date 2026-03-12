# agent-bom: OpenAI, MLflow, Ollama Setup

---

## OpenAI

OpenAI API keys currently do not support scope-limited read-only access — all keys
have the same permissions within their project. Use project-level isolation instead.

Docs: https://platform.openai.com/docs/guides/production-best-practices/api-keys

### Minimum-Liability Setup

1. **Create a dedicated project** in the OpenAI console for agent-bom scanning
   - https://platform.openai.com/settings/organization/projects
   - Name: `agent-bom-scan` — isolates the key from production workloads

2. **Create a project API key** (not an org-level key)
   - Project keys are scoped to one project and cannot access other projects' data
   - https://platform.openai.com/settings/organization/api-keys

3. **Set a spend limit** on the project to prevent unexpected charges
   - The scanner only makes metadata calls (list models, list deployments) — minimal cost

4. **Rotate**: create a new key, update env var, revoke old key

### Usage

```bash
export OPENAI_API_KEY=sk-proj-...
agent-bom scan --openai
```

### What Gets Scanned

- Deployed model names and versions → known vulnerable model versions → findings
- Fine-tuned model metadata → base model lineage
- Assistant configurations → tool definitions → injection pattern scan

---

## MLflow

MLflow has two deployment models with different auth:

### A. Self-Hosted MLflow (most common)

No auth by default. If you've configured auth:
- Basic auth: `MLFLOW_TRACKING_USERNAME` + `MLFLOW_TRACKING_PASSWORD`
- Bearer token: `MLFLOW_TRACKING_TOKEN`

```bash
# Local or unauthenticated remote
export MLFLOW_TRACKING_URI=http://mlflow.internal:5000
agent-bom scan --mlflow

# With token auth
export MLFLOW_TRACKING_URI=https://mlflow.company.com
export MLFLOW_TRACKING_TOKEN=<token>
agent-bom scan --mlflow
```

Docs: https://mlflow.org/docs/latest/auth/index.html

### B. Databricks-managed MLflow (Unity Catalog)

Uses Databricks credentials — see `databricks_readonly.sh`.
The `--databricks` flag covers MLflow on Databricks automatically.

### What Gets Scanned

- Registered model versions → framework + version → CVEs
- Experiment run artifacts → `requirements.txt`, `conda.yaml` → package CVEs
- Model serving endpoints → runtime packages

---

## Ollama

Ollama runs locally and has **no authentication by default**.

```bash
# Local Ollama (default port 11434) — no credentials needed
agent-bom scan --ollama

# Remote Ollama (if OLLAMA_HOST is set)
export OLLAMA_HOST=http://ollama.internal:11434
agent-bom scan --ollama
```

Docs: https://github.com/ollama/ollama/blob/main/docs/api.md

### Security Note

If Ollama is exposed beyond localhost, agent-bom will detect it and flag:
- Unauthenticated remote access (HIGH finding)
- Model names → known vulnerable versions → CVEs
- GGUF/safetensors model provenance

### What Gets Scanned

- Running and available model names/tags → version CVEs
- Model metadata → quantization, format (GGUF, safetensors)
- Endpoint exposure (localhost vs network-accessible)
