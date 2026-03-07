# SBOM Generation

Generate Software Bills of Materials in industry-standard formats.

## Formats

| Format | Standard | Output |
|--------|----------|--------|
| CycloneDX | v1.6 | JSON |
| SPDX | v3.0 | JSON |

## Usage

```bash
# CLI
agent-bom scan --sbom cyclonedx -o sbom.json
agent-bom scan --sbom spdx -o sbom.spdx.json

# MCP tool
generate_sbom(format="cyclonedx")
```

## SBOM ingestion

agent-bom can also ingest existing SBOMs for analysis:

```bash
agent-bom scan --sbom-input existing-sbom.json
```

Supports CycloneDX 1.x and SPDX 2.x/3.0 JSON inputs.

## VEX (Vulnerability Exploitability eXchange)

```bash
# Apply VEX to suppress known non-exploitable findings
agent-bom scan --vex vex-document.json

# Generate VEX from scan results
agent-bom scan --generate-vex --vex-output vex.json
```
