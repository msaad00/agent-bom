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
CycloneDX also supports model and dataset components. Collected cloud inventory
is retained in the scan JSON and connected graph; this does not yet mean that
all cloud assets appear in the standard SBOM exports. Keep the JSON report when
investigating across those sources.

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
