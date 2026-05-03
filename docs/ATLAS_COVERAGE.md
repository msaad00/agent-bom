# MITRE ATLAS Coverage

agent-bom maps blast-radius findings to MITRE ATLAS (Adversarial Threat Landscape
for Artificial-Intelligence Systems). The coverage model is **two-tier**:

1. A **curated tag-surface** of 65 techniques (`src/agent_bom/atlas.py`,
   `ATLAS_TECHNIQUES`). These are the techniques the static, agentless
   blast-radius tagger lights up with high precision.
2. A **bundled reference catalog** of the full upstream ATLAS publication
   (`src/agent_bom/data/mitre_atlas_catalog.json`, fetched from
   [`mitre-atlas/atlas-data`](https://github.com/mitre-atlas/atlas-data)).
   This is reference data only — used to surface "X of N upstream
   techniques covered" rollups in the dashboard, SARIF, and JSON outputs.

The curated set stays load-bearing for tagging precision. The full catalog is
not used for tagging.

## Why a curated subset?

The full upstream catalog (ATLAS 5.6.0 ships 170 techniques + sub-techniques)
covers everything from passive recon through runtime model evasion campaigns.
A static SBOM-style scanner can only observe a subset of those signals. The
curation rules:

- **Include** techniques observable from package metadata, IaC manifests,
  MCP tool capability, exposed credentials, severity, and CVE category.
- **Exclude** techniques that fundamentally require runtime model probing,
  inference-time observation, training-pipeline telemetry, or red-team
  campaign data — tagging those statically would fabricate signal.

If a curated technique drifts out of the upstream catalog, the
`test_atlas_curated_subset_stays_in_upstream_catalog` test in
`tests/test_atlas_fetch.py` fails. Refresh the bundled catalog via
`agent-bom db update-frameworks --framework atlas`, or fix the curated tag
map.

## Refreshing the bundled catalog

```bash
# Refresh both MITRE ATT&CK and ATLAS bundled catalogs locally.
agent-bom db update-frameworks --framework atlas

# Inspect freshness (used by the release-time freshness gate).
agent-bom db framework-status --framework atlas --stale-after-days 180

# Fail-fast in CI (the agent-bom release workflow does exactly this).
agent-bom db framework-status --framework atlas \
  --stale-after-days 180 --fail-on-stale --format json
```

The release workflow gates on the `atlas-catalog-freshness-gate` job, which
mirrors the shape of the `mcp-registry-freshness-gate`.

## Included — curated 65 techniques

| Technique | Name |
|---|---|
| `AML.T0000` | Search Open Technical Databases |
| `AML.T0001` | Search Open AI Vulnerability Analysis |
| `AML.T0002` | Acquire Public AI Artifacts |
| `AML.T0004` | Search Application Repositories |
| `AML.T0005` | Create Proxy AI Model |
| `AML.T0006` | Active Scanning |
| `AML.T0007` | Discover AI Artifacts |
| `AML.T0008` | Acquire Infrastructure |
| `AML.T0010` | AI Supply Chain Compromise |
| `AML.T0010.001` | AI Software |
| `AML.T0010.002` | Data |
| `AML.T0010.003` | Model |
| `AML.T0010.004` | Container Registry |
| `AML.T0011` | User Execution |
| `AML.T0011.001` | Malicious Package |
| `AML.T0012` | Valid Accounts |
| `AML.T0013` | Discover AI Model Ontology |
| `AML.T0014` | Discover AI Model Family |
| `AML.T0015` | Evade AI Model |
| `AML.T0016` | Obtain Capabilities |
| `AML.T0017` | Develop Capabilities |
| `AML.T0018` | Manipulate AI Model |
| `AML.T0018.000` | Poison AI Model |
| `AML.T0018.001` | Modify AI Model Architecture |
| `AML.T0018.002` | Embed Malware |
| `AML.T0019` | Publish Poisoned Datasets |
| `AML.T0020` | Poison Training Data |
| `AML.T0024` | Exfiltration via AI Inference API |
| `AML.T0024.001` | Invert AI Model |
| `AML.T0024.002` | Extract AI Model |
| `AML.T0025` | Exfiltration via Cyber Means |
| `AML.T0029` | Denial of AI Service |
| `AML.T0031` | Erode AI Model Integrity |
| `AML.T0034` | Cost Harvesting |
| `AML.T0035` | AI Artifact Collection |
| `AML.T0036` | Data from Information Repositories |
| `AML.T0037` | Data from Local System |
| `AML.T0040` | AI Model Inference API Access |
| `AML.T0043` | Craft Adversarial Data |
| `AML.T0043.004` | Insert Backdoor Trigger |
| `AML.T0046` | Spamming AI System with Chaff Data |
| `AML.T0048` | External Harms |
| `AML.T0049` | Exploit Public-Facing Application |
| `AML.T0050` | Command and Scripting Interpreter |
| `AML.T0051` | LLM Prompt Injection |
| `AML.T0051.000` | Direct Prompt Injection |
| `AML.T0051.001` | Indirect Prompt Injection |
| `AML.T0052` | Phishing |
| `AML.T0052.000` | Spearphishing via Social Engineering LLM |
| `AML.T0053` | AI Agent Tool Invocation |
| `AML.T0054` | LLM Jailbreak |
| `AML.T0055` | Unsecured Credentials |
| `AML.T0056` | Extract LLM System Prompt |
| `AML.T0057` | LLM Data Leakage |
| `AML.T0063` | Discover AI Model Outputs |
| `AML.T0064` | Gather RAG-Indexed Targets |
| `AML.T0065` | LLM Prompt Crafting |
| `AML.T0066` | Retrieval Content Crafting |
| `AML.T0067` | LLM Trusted Output Components Manipulation |
| `AML.T0068` | LLM Prompt Obfuscation |
| `AML.T0069` | Discover LLM System Information |
| `AML.T0070` | RAG Poisoning |
| `AML.T0071` | False RAG Entry Injection |
| `AML.T0073` | Impersonation |
| `AML.T0074` | Masquerading |

## Excluded — examples and reasons

The full bundled catalog contains 105 additional sub-techniques and
runtime-only techniques. Representative excluded entries:

| Technique | Name | Why excluded |
|---|---|---|
| `AML.T0000.000` | Journals and Conference Proceedings | Recon sub-technique not observable from artifacts agent-bom inspects |
| `AML.T0000.001` | Pre-Print Repositories | Same — passive intel collection signal |
| `AML.T0002.000` | Datasets (Acquire Public AI Artifacts sub) | Acquisition act, not a static observable |
| `AML.T0003` | Search Victim-Owned Websites | Active recon outside agent-bom scope |
| `AML.T0005.000` | Train Proxy via Gathered AI Artifacts | Adversary-side training, requires runtime telemetry |
| `AML.T0005.001` | Train Proxy via Replication | Same |
| `AML.T0008.001` | Consumer Hardware (Acquire Infrastructure sub) | Adversary procurement signal |
| `AML.T0015.x` | Evade AI Model sub-techniques | Inference-time evasion — runtime probing required |
| `AML.T0020.x` | Poison Training Data sub-techniques | Detection requires training-pipeline observability |
| `AML.T0029.x` | Denial of AI Service sub-techniques | Runtime DoS observation |

A technique is excluded if its primary detection signal is **runtime
inference**, **training-pipeline telemetry**, or **red-team campaign
intelligence**, none of which are available to a static, agentless scanner.

## Surface

- **CLI / JSON / SARIF**: every blast-radius row carries `atlas_tags`.
- **API**: `GET /v1/frameworks/catalogs` returns `frameworks.mitre_atlas`
  with `atlas_version`, `technique_count`, `curated_count`, and source hash.
- **Dashboard**: `/compliance` surfaces a MITRE ATLAS catalog rollup tile
  showing curated coverage vs upstream technique count.
