# SBOM Generation

Generate Software Bills of Materials in industry-standard formats.

## Formats

| Format | Standard | Output |
|--------|----------|--------|
| `cyclonedx` | CycloneDX 1.7 | JSON |
| `spdx` | SPDX 3.0.1 | JSON-LD |
| `spdx2` | SPDX 2.3 | JSON |

## Usage

```bash
# Scan a repository and save a standard BOM
agent-bom scan . -f cyclonedx -o sbom.json
agent-bom scan . -f spdx -o sbom.spdx.json
agent-bom scan . -f spdx2 -o sbom.spdx2.json

# MCP tool
generate_sbom(format="cyclonedx")
```

## Inspect component hierarchy

Open `sbom.json` and follow its `dependencies` references from an agent or
server to a direct package, then to its recorded transitive dependencies.
SPDX uses native dependency relationships and retains server membership for
transitive packages. A package shared by several servers retains each observed
relationship.

A parent is resolved only within the same server inventory and ecosystem. A
missing parent, multiple matching versions, or a self-reference stays unresolved;
no dependency is borrowed from another server or environment. CycloneDX marks
such a composition incomplete; SPDX includes an unresolved-parent annotation.
The current package model retains one introducing parent, so this is not a
claim that every dependency path was collected.

These standard exports include agents, MCP servers and software packages.
CycloneDX also supports model and dataset components.

## Keep cloud context with the BOM

When a scan collects `cloud_inventory`, standard exports retain that snapshot
in the versioned `agent-bom:cloud-inventory:v1` extension:

| Format | Extension location |
|--------|--------------------|
| CycloneDX | `metadata.properties` entry; parse its `value` as JSON |
| SPDX 3 | Document `Annotation` with `contentType: application/json`; parse `statement` |
| SPDX 2 JSON | Document `annotations`; parse `comment` |
| SPDX 2 tag-value | JSON in `DocumentComment` |

The extension retains provider-native resource IDs, account/subscription/project
scope, resource tags and labels, discovery metadata, and collection status or
warnings present in the input. Equal display names stay in their original
provider/account records. No software dependency or cross-source relationship is
inferred from a matching name. Cloud records remain evidence in the extension;
they are not relabeled as software packages.

The envelope has `schema_version: 1`, `source: cloud_inventory`,
`coverage: not_assessed`, a `redaction` policy description, and the `inventory`
payload. A collector's `status: ok` does not establish complete account coverage.
Denied, partial and explicitly empty payloads are retained; absent inventory
omits the extension. Structured secret/path redaction applies before encoding,
with 1,000-character string and 24-level nesting limits. Valid Azure ARM IDs
receive cloud-identifier redaction rather than local-path masking.

Generic SBOM readers may ignore this namespaced extension. The SBOM import path
extracts software packages; it does not restore cloud inventory from the
extension. Keep the original export and scan JSON for cloud investigation and
graph correlation. Separate benchmark results and runtime evidence are not
included in this cloud-inventory snapshot.

From a source checkout, run the credential-free example:

```bash
uv run python scripts/prove_connected_bom.py --output-dir /tmp/connected-bom-example
jq '.metadata.properties[] | select(.name == "agent-bom:cloud-inventory:v1") | .value | fromjson' \
  /tmp/connected-bom-example/before.cyclonedx.json
```

Choose a new output directory. The example parses and scans a real dependency
manifest against a pinned offline advisory, changes the declared version, and
writes before/after BOMs in all three JSON formats alongside graph evidence and
a rescan diff. Its AWS, Azure and GCP records are labeled synthetic examples;
this command does not authenticate to a cloud provider. Inspect `inventory` for
the three same-name resources and their distinct native scopes, then compare
the before/after software findings.

## SBOM ingestion

agent-bom can also ingest existing SBOMs for analysis:

```bash
agent-bom scan --sbom existing-sbom.json -f json -o sbom-report.json
```

Supports CycloneDX 1.x and SPDX 2.x/3.0 JSON inputs. The scan preserves the
packages and versions supplied by the SBOM; neighboring manifests do not add or
replace packages. Open `sbom-report.json` to inspect the resulting findings.
Use `agent-bom scan -p <project>` when the intended scope is the project tree.

## VEX (Vulnerability Exploitability eXchange)

```bash
# Apply VEX to suppress known non-exploitable findings
agent-bom agents --vex vex-document.json

# Generate VEX from scan results
agent-bom agents --generate-vex --vex-output vex.json
```
