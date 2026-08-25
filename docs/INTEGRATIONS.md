# Integration capability matrix

The marks in the README header identify supported product surfaces. They do
not all mean the same kind of connector, and they do not imply identical depth.
This matrix names the shipped role and a direct way to verify it.

| Marks | Role | Shipped capability | First proof |
|---|---|---|---|
| Claude, Cursor, GitHub Copilot, Windsurf, Codex CLI, VS Code, Cortex Code | Client discovery | Discover local and project MCP/client configuration, instruction files, servers, tools, packages, and relationships. These are configuration discovery paths, not vendor-account API connections. | `agent-bom where --json`, then `agent-bom scan .` |
| AWS, Azure, GCP | Read-only cloud connection | Connect with provider-native credentials; inventory cloud and AI assets; run posture, IAM, and benchmark checks with explicit permission gaps. | `agent-bom connect aws --emit --out agent-bom-aws-readonly.json`, deploy it, then connect with its outputs |
| Kubernetes | Scan and deploy | Scan Kubernetes and Helm configuration, inspect live cluster posture when access is supplied, and deploy the self-hosted control plane with Helm. | `agent-bom iac k8s/`; see [Kubernetes deployment](../site-docs/deployment/kubernetes.md) |
| Okta | Identity | Use Okta as an OIDC provider and optionally run gated, read-only non-human identity discovery. This is not presented as a full Okta CSPM connector. | `agent-bom identity discover --provider okta --format json` |
| Snowflake | Data platform | Read-only source and posture evidence, Native App packaging, and selected warehouse-backed product paths. | `agent-bom connect snowflake`; see [cloud connections](CLOUD_CONNECT.md#6-snowflake--connect-with-a-key-pair-never-a-password) |
| Databricks | Data platform | SDK-backed discovery of clusters, libraries, and model-serving endpoints plus read-only security best-practice checks. | `agent-bom scan --databricks --databricks-security` |
| ClickHouse | Analytics backend | Optional tenant-scoped analytics store for findings, posture history, trends, and runtime events. It is a backend, not a scanned cloud account. | `agent-bom report analytics --clickhouse-url URL` |

Across these surfaces, raw credential values remain in the operator boundary.
Connections use environment references, provider credential chains, or
customer-managed secrets; partial permissions remain visible in scan outcomes.

See [product boundaries](PRODUCT_BOUNDARIES.md), [cloud connections](CLOUD_CONNECT.md),
and [agentic workflows](../site-docs/reference/agentic-workflows.md) for the
exact credential, artifact, and next-step contracts.
