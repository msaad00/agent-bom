# AI-BOM coverage map

`agent-bom` treats an AI-BOM as a relationship-backed security record, not a
static checklist. The useful object is not just "which model exists." It is:

```text
AI system -> data -> model -> dependencies -> infrastructure -> identities
          -> controls -> owners -> runtime and change evidence
```

The scanner should stay honest about the boundary it inspected. A local scan can
prove repo, package, model-file, dataset-card, and MCP configuration evidence. A
cloud scan can prove provider-visible AI services, identity, network, registry,
Kubernetes, and GPU evidence when read-only credentials are supplied. Runtime
proxy, gateway, Shield, or trace evidence is required before claiming live
tool-call behavior.

This page is intentionally repo-backed. If a layer below says "records today,"
there is a code path, API path, output formatter, test, skill, or public docs
surface that supports it. If the evidence is partial, the table says so.

## Code-backed entry points

| Surface | First command or API path | Artifact | Code or docs anchor |
|---|---|---|---|
| Local agents, MCP, packages, and credential references | `agent-bom agents -p . -f json -o ai-bom.json` | AI-BOM JSON, findings, graph-ready inventory | `src/agent_bom/cli/agents/`, `src/agent_bom/models.py`, `src/agent_bom/output/json_fmt.py` |
| Model files and manifests | `agent-bom mcp server` then `model_file_scan` tool, or API scan route | model file list, unsafe-format flags, manifests | `src/agent_bom/model_files.py`, `src/agent_bom/mcp_tools/specialized.py`, `src/agent_bom/api/routes/scan.py` |
| Model provenance | `agent-bom cloud model-provenance <org/model>` | Hub metadata, hash/signature/provenance evidence where available | `src/agent_bom/cloud/model_provenance.py`, `src/agent_bom/cli/cloud.py` |
| Dataset cards and PII-oriented dataset evidence | dataset scan API/MCP specialized scanner | dataset metadata, license/source/version hints, warnings | `src/agent_bom/parsers/dataset_cards.py`, `src/agent_bom/parsers/dataset_pii_scanner.py` |
| Training pipeline evidence | training-pipeline scan API/MCP specialized scanner | training run metadata, framework/source tags | `src/agent_bom/parsers/training_pipeline.py`, `tests/test_training_pipeline.py` |
| Cloud, GPU, Kubernetes, and AI infrastructure | `agent-bom agents --preset enterprise`, `--gpu-scan`, `--k8s`, provider flags | provider-visible AI resources, workloads, GPU/firmware signals, findings | `src/agent_bom/cloud/`, `src/agent_bom/scanners/firmware_advisory.py`, `site-docs/architecture/ai-infrastructure.md` |
| Runtime proxy and gateway | `agent-bom proxy ...`, `agent-bom gateway serve ...` | audit JSONL, policy decisions, runtime alerts | `src/agent_bom/proxy_server.py`, `src/agent_bom/gateway_server.py`, `site-docs/features/runtime-proxy.md` |
| SBOM and compliance evidence | `agent-bom agents -p . -f cyclonedx`, `-f spdx`, compliance export paths | CycloneDX, SPDX, compliance evidence bundles | `src/agent_bom/output/cyclonedx_fmt.py`, `src/agent_bom/output/spdx_fmt.py`, `src/agent_bom/api/routes/compliance.py` |

## Skills and guided workflows

Skills are distribution surfaces for repeatable AI-BOM workflows. They are not
separate product claims; they should call the same scanner, output, graph, and
compliance paths above.

| Skill surface | Purpose | Evidence boundary |
|---|---|---|
| `docs/skills/ai-bom-generator.md` | Guides local, image, Kubernetes, cloud, IaC, CI, and unified AI-BOM generation. | Breadth guide; each command still only proves the target boundary it can inspect. |
| `docs/skills/compliance-export.md` | Guides CycloneDX, SPDX, SARIF, and framework evidence export. | Compliance evidence aid, not a complete audit by itself. |
| `docs/skills/owasp-llm-assessment.md` | Guides OWASP LLM + MITRE ATLAS assessment. | Threat mapping must be tied to scan findings and runtime evidence where applicable. |
| `docs/skills/pre-deploy-gate.md` | Guides CI/pre-deploy gating. | CI evidence is build-time evidence, not proof of deployed runtime state. |
| `site-docs/reference/agentic-workflows.md` | Maps workflows to commands, credential boundaries, artifacts, and next steps. | Public first-run and integration path; should stay aligned with implemented commands. |

## Seven-layer implementation map

| AI-BOM layer | What agent-bom records today | Evidence paths | Readiness | Next hardening PR |
|---|---|---|---:|---|
| Data | Dataset cards, DVC metadata, dataset license/source/version hints, PII-oriented dataset scan output, graph `DATASET` nodes where dataset cards are present. | `src/agent_bom/parsers/dataset_cards.py`, `src/agent_bom/parsers/dataset_pii_scanner.py`, `src/agent_bom/graph/builder.py`, `src/agent_bom/api/routes/scan.py` | 70% | Promote dataset PII and missing-license findings into the unified finding stream and add model-to-dataset lineage edges. |
| Model | Local model files, risky serialization formats, model manifests, Hub provenance, hash/signature evidence where available, model supply-chain advisory data. | `src/agent_bom/model_files.py`, `src/agent_bom/cloud/model_provenance.py`, `src/agent_bom/data/ai_model_advisories.json`, `src/agent_bom/models.py` | 68% | Normalize `model_files`, `model_manifests`, and `model_provenance` into one contract-tested model asset shape. |
| Dependency | Package inventory, direct/transitive depth, PURLs, CVEs/GHSAs/OSV, license data, malicious package indicators, CycloneDX and SPDX exports. | `src/agent_bom/models.py`, `src/agent_bom/scanner_drivers.py`, `src/agent_bom/output/cyclonedx_fmt.py`, `src/agent_bom/output/spdx_fmt.py`, `contracts/v1/scan-report.schema.json` | 85% | Add stricter end-to-end schema tests for ML/SBOM extensions so downstream consumers cannot drift silently. |
| Infrastructure | Containers, Kubernetes, GPU/firmware signals, cloud AI providers, vector databases, registry evidence, IaC findings, graph cloud-resource nodes. | `src/agent_bom/cloud/`, `src/agent_bom/cli/options_surfaces.py`, `src/agent_bom/graph/types.py`, `site-docs/architecture/ai-infrastructure.md` | 78% | Connect provider, cloud resource, workload, model, dataset, package, and agent nodes with stable graph edges. |
| Security and governance | Credential environment names, MCP tool permissions, policy decisions, audit logs, compliance mappings, signed evidence bundles, tenant/auth boundaries. | `src/agent_bom/governance.py`, `src/agent_bom/api/audit_log.py`, `src/agent_bom/api/routes/compliance.py`, `src/agent_bom/api/compliance_signing.py`, `site-docs/features/compliance.md` | 82% | Add AI-specific control evidence for datasets, training pipelines, model provenance, and runtime policy events. |
| People and process | Trust assessment, skill review evidence, governance APIs, graph identity node types, audit trails for control-plane mutations. | `src/agent_bom/parsers/trust_assessment.py`, `src/agent_bom/parsers/skill_audit.py`, `src/agent_bom/api/routes/governance.py`, `src/agent_bom/graph/types.py` | 58% | Add owner, steward, approver, review cadence, and exception-owner fields for AI assets. |
| Usage and documentation | Agentic workflow matrix, MCP tool reference, security graph contract, runtime docs, compliance pages, API/UI drill-down surfaces. | `site-docs/reference/agentic-workflows.md`, `site-docs/reference/mcp-tools.md`, `site-docs/architecture/security-graph-model.md`, `docs/graph/CONTRACT.md` | 75% | Publish a sample seven-layer AI-BOM report and one command-to-artifact path per layer. |

The readiness values are local repo readiness estimates, not certification
scores. They are meant to drive engineering priority: the scanner already sees
many components, while the public JSON contract, graph edges, and UI detail
panels need tighter normalization for some AI-native assets.

## Security functions enabled by the AI-BOM

| Function | How agent-bom supports it | Evidence boundary |
|---|---|---|
| Discovery and inventory | Finds agents, MCP servers, packages, model files, dataset cards, cloud AI services, containers, Kubernetes, GPU surfaces, IaC, and runtime proxy/gateway events. | The scan target and credentials decide what can be proven. |
| Traceability and explainability | Builds graph relationships among agents, servers, tools, packages, credentials, vulnerabilities, datasets, cloud resources, and runtime events. | Static graph edges can prove reachability and exposure; live causality needs runtime evidence. |
| Risk assessment and prioritization | Uses severity, KEV/EPSS, package depth, direct exposure, tool capability, credential exposure, and graph blast radius to sort findings. | Findings should show why they are prioritized, not just report a CVE count. |
| Governance and compliance | Maps findings to OWASP LLM/MCP/Agentic, MITRE ATLAS, NIST AI RMF, NIST CSF, ISO 27001, SOC 2, CIS, CMMC, FedRAMP, EU AI Act, and PCI DSS subsets. | These are curated evidence mappings, not complete framework catalogs. |
| Change management and incident response | Baselines scan output, exports evidence, supports fleet/control-plane state, and can answer which agents, servers, packages, credentials, and workloads are in blast radius. | Rotation or rollback decisions should combine scan evidence with provider logs, SIEM, endpoint, and billing data. |

## Incident-class mapping

AI supply-chain incidents often cross model artifacts, shared inference
infrastructure, container registries, identities, metadata services, and runtime
execution. A complete AI-BOM should make those relationships queryable.

For a model deserialization or shared-inference isolation scenario, `agent-bom`
should model the following evidence:

| Risk question | AI-BOM evidence needed | Current source |
|---|---|---|
| Is an unsafe model format present? | Model file path, format, hash, size, and unsafe serialization flag. | `model_files.py` detects pickle/joblib and other model formats. |
| Which serving or training surface can load it? | Serving config, training pipeline, container image, workload, and runtime dependency edges. | Partial through `training_pipelines`, `serving_configs`, container scans, and graph nodes. |
| Could a workload reach cloud metadata or sensitive data? | Cloud identity, Kubernetes workload, network path, IMDS or metadata-service exposure, dataset/data-store edges. | Partial through cloud, Kubernetes, IaC, and graph evidence. |
| Is registry or artifact access too broad? | Image registry, package provenance, model provenance, access policy, and owner evidence. | Partial through container SBOM, model provenance, and governance surfaces. |
| What must rotate after exposure? | Credential env names, MCP servers, agents, cloud roles, CI jobs, workloads, datasets, and provider integrations in blast radius. | Strong for MCP/agent/package credentials; partial for cloud role and dataset lineage. |

## Truth boundaries

- `agent-bom` does not execute untrusted model artifacts to inspect them.
- Static scans do not prove a tool call happened. Runtime proof requires proxy,
  gateway, Shield, trace, or platform log evidence.
- Credential values should not be stored. The AI-BOM records credential names,
  boundaries, and references where possible.
- Provider and cloud scans should use read-only credentials. Missing provider
  permissions are partial evidence, not a product failure.
- Compliance mappings are evidence aids. They do not replace an auditor,
  control owner, or legal review.

## Best next implementation sequence

1. Canonicalize AI asset schema for `model_files`, `model_manifests`,
   `model_provenance`, `dataset_cards`, `training_pipelines`, `serving_configs`,
   and `ai_inventory_data`.
2. Add graph ingestion for the canonical AI assets and preserve omitted-count
   summaries for large graphs.
3. Add UI detail panels for the seven AI-BOM layers with source artifact links,
   confidence, and "not observed" states.
4. Add incident-response queries for model deserialization, credential exposure,
   registry exposure, IMDS exposure, and runtime tool-call policy blocks.
5. Publish a sample seven-layer AI-BOM report with JSON, graph, CycloneDX/SPDX,
   compliance, and runtime evidence variants.

## References

- [OWASP AI BOM project](https://owaspaibom.org/)
- [OWASP AI BOM generator](https://genai.owasp.org/resource/owasp-aibom-generator/)
- [Wiz AI-BOM overview](https://www.wiz.io/academy/ai-security/ai-bom-ai-bill-of-materials)
