# AI Infrastructure Scanning

For the comprehensive guide, see [AI_INFRASTRUCTURE_SCANNING.md](https://github.com/msaad00/agent-bom/blob/main/docs/AI_INFRASTRUCTURE_SCANNING.md).

For the seven-layer AI-BOM evidence map, see
[AI-BOM coverage map](ai-bom-coverage.md).

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

## Credential Boundaries

Use read-only credentials for provider scans. A provider scan proves only the
account, workspace, namespace, registry, or local endpoint that credential can
inspect; it does not prove all deployed AI systems unless those systems are in
that boundary.

| Surface | First command | Credential boundary | Data read | Artifact |
|---|---|---|---|---|
| AWS AI and GPU infrastructure | `agent-bom agents --preset enterprise --aws` | AWS profile, role, or web identity with read-only inventory permissions | account, region, EKS/ECS/Lambda/IAM/S3 and AI-service metadata visible to the role | JSON/HTML findings, graph-ready cloud inventory, CIS evidence when enabled |
| Azure AI surfaces | `agent-bom agents --preset enterprise --azure` | Azure identity or service principal scoped to selected subscriptions/resource groups | Azure AI, container, identity, and resource metadata visible to the principal | JSON/HTML findings and cloud inventory |
| GCP Vertex AI and cloud resources | `agent-bom agents --preset enterprise --gcp` | ADC or service account scoped to selected projects | Vertex AI, IAM, storage, compute, and project metadata visible to the service account | JSON/HTML findings and cloud inventory |
| Snowflake AI Data Cloud | `agent-bom agents --preset enterprise --snowflake` | Snowflake role/user scoped by warehouse, database, schema, and account grants | Cortex, warehouse, role, object, task, stream, and query metadata visible to the role | Snowflake posture evidence and compliance-ready inventory |
| Databricks workspaces | `agent-bom agents --preset enterprise --databricks` | Databricks host/token or configured workspace identity | workspace, cluster/job, model, secret-scope names, and notebook metadata visible to the token | workspace inventory and findings |
| Hugging Face model and registry evidence | `agent-bom agents -p . --enrich` or provider-specific scan path | public Hub access or optional token for private model metadata | model card, repository, file, license, and provenance metadata visible to the caller | model provenance and supply-chain evidence |
| OpenAI and hosted model providers | `agent-bom agents -p .` plus provider inventory where configured | repo-local code/config and any configured read-only provider inventory token | SDK imports, model names, endpoint references, and provider-visible metadata where supported | AI inventory, provider references, and graph-ready model/service nodes |
| W&B, MLflow, and observability tools | `agent-bom agents -p .` plus configured provider scan | workspace/project token scoped by the provider | experiment, run, model registry, and trace metadata visible to the token | MLOps inventory and related findings |
| Ollama and local model runtimes | `agent-bom agents --preset enterprise --ollama` | local endpoint access on the inspected host or network boundary | local model/runtime metadata exposed by the endpoint | local model runtime inventory |

Credential values should not be stored in scan artifacts. Outputs may include
credential environment variable names, role names, account identifiers,
workspace names, and source paths needed for investigation.
