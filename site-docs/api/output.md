# Output

Output formatters for console, JSON, HTML, SARIF, CycloneDX, SPDX, and other formats.

Generate reviewable artifacts from a scan:

```bash
agent-bom scan --demo --offline --format json --output findings.json
```

Review the finding's advisory, affected product and reachability before assigning
an impact. Missing impact metadata remains unspecified in SARIF; legacy scan
records use `unknown`. Broad input-validation CWEs alone do not establish data
loss or code execution. The original advisory description remains evidence for
reviewing the effect and its preconditions.

Generated VEX groups only equivalent assessments and retains every affected
product PURL. Different versions or suppression decisions are not discarded just
because they share a CVE. Review those product-specific statements before using
VEX to suppress findings downstream.

::: agent_bom.output
    options:
      members:
        - print_summary
        - print_compact_summary
        - print_compact_agents
        - print_compact_blast_radius
        - print_blast_radius
        - export_json
        - export_html
        - export_sarif
        - export_cyclonedx
        - export_spdx
        - SEVERITY_BADGES
        - SEVERITY_TEXT
