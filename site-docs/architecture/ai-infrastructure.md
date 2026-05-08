# AI Infrastructure Scanning

For the comprehensive guide, see [AI_INFRASTRUCTURE_SCANNING.md](https://github.com/msaad00/agent-bom/blob/main/docs/AI_INFRASTRUCTURE_SCANNING.md).

## Supported infrastructure

| Layer | What we scan |
|-------|-------------|
| **MCP Clients** | 29 first-class client types — Claude, Cursor, VS Code, Windsurf, Cline, Codex, Gemini, Goose, etc. |
| **MCP Servers** | Package deps, tool definitions, credential exposure, description drift |
| **Container Images** | Native OCI package discovery across OS and language packages |
| **Kubernetes** | Namespace enumeration, pod MCP detection |
| **Cloud** | AWS, Snowflake, Azure ML, GCP Vertex AI, Databricks, HuggingFace, Ollama |
| **AI observability** | LangSmith, Langfuse, Braintrust, Arize/Phoenix, Trubrics, Helicone SDK inventory |
| **Code** | SAST via Semgrep with CWE mapping |

## Coverage Matrix

Use this matrix when deciding which AI infrastructure path to run first. The
command should match the system boundary you can actually inspect.

| Surface | First command | Evidence produced | Credential boundary | Current limit |
|---|---|---|---|---|
| Local agent and MCP inventory | `agent-bom agents -p .` | agents, MCP servers, packages, credential env-var names, findings | local filesystem and project checkout | static scan; no live tool-call causality |
| Skills and instruction files | `agent-bom skills scan .` | instruction-file findings, referenced packages, MCP mentions, trust notes | repo-local docs and skill files | does not prove a skill is installed in every assistant |
| Container and GPU images | `agent-bom agents --image <image>` | OS and language packages, CVEs, SBOM-ready package inventory | registry pull credentials when private images are used | image scan does not prove runtime deployment |
| Kubernetes and GPU workloads | `agent-bom agents --k8s --namespace <ns>` | pod/workload inventory, package paths where available, GPU workload context | kubeconfig or in-cluster service account | depends on Kubernetes permissions and visible namespaces |
| Cloud and AI platforms | provider-specific scan flags or enterprise preset | read-only cloud, warehouse, model, and AI service inventory | customer-managed provider credentials | provider coverage varies; mark partial evidence honestly |
| IaC and repo posture | `agent-bom iac scan .` or CI action | Terraform, Kubernetes, Helm, CloudFormation, Dockerfile findings | repository checkout | planned resources are not proof of deployed state |
| Runtime proxy or gateway | `agent-bom proxy ...` or `agent-bom gateway serve ...` | audit JSONL, policy decisions, runtime alerts, relay metrics | selected MCP traffic path and operator runtime tokens | only selected traffic is governed |

## Evidence Rules

- Keep scan-only evidence separate from runtime evidence. Static findings show
  reachability and exposure; proxy, gateway, trace, or Shield evidence is
  required for live tool-call causality.
- Record the command, target boundary, artifact path, and credential source in
  release notes or buyer demos.
- Treat provider entries marked partial as explicit gaps, not as silent
  coverage.
- Prefer read-only credentials for cloud, warehouse, model, and registry scans.
- Do not imply endpoint, gateway, or proxy rollout unless the runtime command
  path was actually run.

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
