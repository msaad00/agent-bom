# ADR-003: CycloneDX as primary SBOM format

## Status

Accepted

## Context

agent-bom generates SBOMs (Software Bill of Materials) from scan results.
Two dominant standards exist:

1. **CycloneDX** — OWASP project, JSON/XML, strong security focus (VEX, VDR),
   versioned schema (1.4–1.6), Python library (`cyclonedx-python-lib`)
2. **SPDX** — Linux Foundation / ISO standard, broader scope (licensing focus),
   JSON/RDF/tag-value, more complex data model

Both are required by various compliance frameworks (EU CRA, US EO 14028).

## Decision

Use **CycloneDX 1.6** as the primary SBOM output format, with SPDX 3.0 as a
secondary export option.

- `generate_sbom` MCP tool and `--sbom-format` CLI flag default to CycloneDX
- SPDX export is available via `--sbom-format spdx`
- SBOM ingest (`--sbom` flag) accepts both CycloneDX 1.x and SPDX 2.x/3.0

We also support VEX (Vulnerability Exploitability eXchange) via `--vex` / `--generate-vex`
using the OpenVEX format, which pairs naturally with CycloneDX.

## Consequences

### Positive

- CycloneDX's security-first design aligns with agent-bom's mission
- `cyclonedx-python-lib` provides validated serialization (already a dependency)
- VEX integration enables "not affected" / "false positive" annotations
- Both major standards supported for compliance flexibility

### Negative

- Some government contracts prefer SPDX — secondary support mitigates this
- CycloneDX 1.6 is newer, some tools may not fully support it yet
- Maintaining two SBOM serializers adds code surface
