# Data sources — mechanism and permission map

One-page map from the README intake diagram to the **actual connect path**,
**permission boundary**, and **first command**. agent-bom is **read-only by
default** across every lane: no secret values stored, no writes to customer
environments unless an operator explicitly opts into a documented exception
(AWS side-scan snapshot lifecycle).

## How intake works (four modes)

| Mode | When to use | Permission model |
|---|---|---|
| **Direct scan** | Local repo, CI job, MCP config on disk, image tarball, IaC tree, SBOM file | Reads files/processes the operator already controls; see [PERMISSIONS.md](PERMISSIONS.md) |
| **Read-only cloud role** | AWS, Azure, GCP, Snowflake estate inventory | Customer-managed IAM/RBAC/key-pair; agent-bom assumes or uses creds at scan time only |
| **API push / ingest** | Fleet sync, scan report upload, findings bulk, OCSF traces | Control-plane API key / OIDC / SAML; tenant-scoped write to *your* agent-bom instance |
| **Optional in-env collector** | Endpoint fleet timer, Helm scan CronJob, proxy/gateway sidecar | Deployed in customer boundary; pushes metadata/evidence to control plane |

Deep architecture: [site-docs/architecture/data-ingestion-and-security.md](../site-docs/architecture/data-ingestion-and-security.md) ·
cloud grants: [CLOUD_CONNECT.md](CLOUD_CONNECT.md)

## Diagram tile → mechanism

| Source | Mechanism | Enable / first command | Permission boundary |
|---|---|---|---|
| **Repo** | Direct scan (filesystem + lockfiles) | `agent-bom agents -p .` | Local read-only; no network unless enrichment enabled |
| **CI** | Direct scan in pipeline + optional push | `uses: msaad00/agent-bom@v…` or `agent-bom agents … --push-url …/v1/results/push` | CI runner filesystem; push uses API key to *your* control plane |
| **MCP** | Config discovery + optional live introspection | `agent-bom agents -p .` or `agent-bom mcp introspect` | Reads MCP configs; no credential values |
| **Image** | Container image scanner driver | `agent-bom image <ref>` | Local daemon/registry/tarball read |
| **IaC** | Terraform/K8s/Helm scanner drivers | `agent-bom iac -p .` | Local/IaC tree read-only |
| **SBOM** | SBOM import driver | `agent-bom sbom ingest <file>` | Parses supplied artifact only |
| **Model** | Model advisory / Hugging Face paths | `agent-bom agents --huggingface` (etc.) | Token read from env at runtime; never stored |
| **AWS** | Read-only IAM role (`SecurityAudit` + optional `ViewOnlyAccess`) | `agent-bom connect aws` → `AGENT_BOM_AWS_INVENTORY=1` → `agent-bom cloud aws` | [connect-aws](../deploy/terraform/connect-aws/README.md); STS `AssumeRole` + `ExternalId` for org fan-out |
| **Azure** | `Reader` + `Security Reader` | `agent-bom connect azure` → `AGENT_BOM_AZURE_INVENTORY=1` → `agent-bom cloud azure` | [connect-azure](../deploy/terraform/connect-azure/README.md); `DefaultAzureCredential` chain |
| **GCP** | Read-only inventory, IAM review, Cloud Asset, and service-usage roles | `agent-bom connect gcp` → `AGENT_BOM_GCP_INVENTORY=1` → `agent-bom cloud gcp` | [connect-gcp](../deploy/terraform/connect-gcp/README.md); ADC / SA key JSON |
| **Snowflake** | `ABOM_READONLY` role; key-pair JWT or browser SSO | `pip install 'agent-bom[snowflake]'` → `agent-bom connect snowflake` → `agent-bom agents --snowflake` | [connect-snowflake](../deploy/terraform/connect-snowflake/README.md); Python connector auth — no `snowsql` session required |

### Snowflake quick path

```bash
pip install 'agent-bom[snowflake]'
# One-time (ACCOUNTADMIN): deploy ABOM_READONLY grant — see scripts/provision/snowflake_readonly.sql
export SNOWFLAKE_ACCOUNT=xy12345
export SNOWFLAKE_USER=AGENT_BOM
export SNOWFLAKE_WAREHOUSE=COMPUTE_WH
# Default: browser SSO (externalbrowser). CI: SNOWFLAKE_AUTHENTICATOR=snowflake_jwt + SNOWFLAKE_PRIVATE_KEY_PATH
agent-bom agents --snowflake
```

## Control-plane ingest API (push evidence)

| Route | Purpose | CLI / client |
|---|---|---|
| `POST /v1/fleet/sync` | Endpoint inventory sync | `agent-bom agents --push-url …/v1/fleet/sync` |
| `POST /v1/results/push` | Full scan report → ScanJob | `agent-bom agents … --push-url …/v1/results/push` |
| `POST /v1/findings/bulk` | Normalized findings batch | API / integrations |
| `POST /v1/ocsf/ingest` | OCSF security events | SIEM / observability hooks |
| `POST /v1/sources` + `POST /v1/sources/{id}/run` | Registered connector/source registry | Dashboard **Scan → Sources** |

Hosted source kinds (`scan.*`, `connector.*`, `ingest.*`, `runtime.*`) are defined in `src/agent_bom/api/models.py` (`SourceKind`).

## Optional deploy-in-target collectors

| Collector | Role |
|---|---|
| Endpoint fleet timer / plist | Periodic `agent-bom agents` + `POST /v1/fleet/sync` |
| Helm scanner CronJob | In-cluster scheduled scan (`deploy/helm/agent-bom` values) |
| Proxy / gateway sidecar | Runtime audit + policy enforcement |
| AWS side-scan | **Opt-in** snapshot lifecycle (non-read-only exception); see `deploy/terraform/connect-aws-sidescan/` |

## Related docs

- [PRODUCT_MAP.md](PRODUCT_MAP.md) — lanes and surfaces
- [FIRST_RUN.md](FIRST_RUN.md) — local first scan
- [DEPLOY_PLATFORM.md](DEPLOY_PLATFORM.md) — self-host the control plane
- [MCP_SERVER.md](MCP_SERVER.md) — agent tool intake (`ingest_external_scan`)
