# Compliance Export

> Generate audit-ready AI-BOM documents in CycloneDX, SPDX, and SARIF with OWASP LLM Top 10 + MITRE ATLAS coverage matrix.

## Goal

Produce compliance-ready artifacts for auditors, regulators, and security teams: standardized SBOM formats (CycloneDX 1.6, SPDX 3.0), SARIF for GitHub Security, threat framework coverage reports, and an interactive HTML dashboard.

## Prerequisites

```bash
pip install agent-bom
# For cloud providers: pip install 'agent-bom[cloud]'
```

## Steps

### 1. Full Inventory Scan

Run the most comprehensive scan available for your environment:

```bash
agent-bom scan \
  [your discovery flags: --aws, --snowflake, --k8s, --image, etc.] \
  --enrich \
  --verify-integrity \
  -f json -o full-inventory.json
```

Key flags for compliance:
- `--enrich` — adds NVD CVSS scores, EPSS probabilities, CISA KEV status
- `--verify-integrity` — checks SHA256/SRI hashes and SLSA provenance against registries

### 2. CycloneDX 1.6 Export

The industry standard SBOM format for AI supply chain:

```bash
agent-bom scan [your flags] --enrich -f cyclonedx -o ai-bom.cdx.json
```

Includes:
- Component inventory (agents, servers, packages)
- Vulnerability list with CVSS + references
- Dependency relationships
- License information
- CycloneDX 1.6 `formulation` for AI components

### 3. SPDX 3.0 Export

ISO/IEC 5962:2021 standard:

```bash
agent-bom scan [your flags] --enrich -f spdx -o ai-bom.spdx.json
```

Includes:
- Package SPDX identifiers
- Relationship graph (DEPENDS_ON, CONTAINS)
- Security vulnerability references
- License expressions (SPDX format)

### 4. SARIF Export

Static Analysis Results Interchange Format for GitHub Security:

```bash
agent-bom scan [your flags] --enrich -f sarif -o results.sarif
```

SARIF output includes:
- OWASP LLM tags in `result.properties`
- MITRE ATLAS technique IDs
- Severity levels mapped to SARIF levels
- File locations (where configs are found)

Upload to GitHub:

```bash
# Via GitHub CLI
gh api repos/<owner>/<repo>/code-scanning/sarifs \
  -f sarif="$(cat results.sarif | base64)"
```

Or via GitHub Actions:

```yaml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### 5. Threat Framework Coverage Report

The JSON output includes a complete threat framework summary:

```bash
agent-bom scan [your flags] --enrich -f json -o report.json
```

Extract the coverage matrix:

```bash
python3 -c "
import json
report = json.load(open('report.json'))
summary = report.get('threat_framework_summary', {})

print('=== OWASP LLM Top 10 ===')
for item in summary.get('owasp_llm_top10', []):
    status = 'TRIGGERED' if item['triggered'] else '-'
    print(f\"  {item['code']}: {item['name']} — {item['findings']} findings [{status}]\")

print(f\"\nTotal OWASP categories triggered: {summary.get('total_owasp_triggered', 0)}\")

print('\n=== MITRE ATLAS ===')
for item in summary.get('mitre_atlas', []):
    status = 'TRIGGERED' if item['triggered'] else '-'
    print(f\"  {item['technique_id']}: {item['name']} — {item['findings']} findings [{status}]\")

print(f\"Total ATLAS techniques triggered: {summary.get('total_atlas_triggered', 0)}\")
"
```

### 6. HTML Dashboard

Interactive dashboard for non-technical stakeholders:

```bash
agent-bom scan [your flags] --enrich -f html -o compliance-report.html
```

Includes:
- Severity donut chart
- Blast radius table
- Dependency graph (Cytoscape.js)
- Threat framework coverage matrix
- Remediation plan with impact bars

### 7. Integrity Verification

Verify package provenance and checksums:

```bash
agent-bom scan [your flags] --verify-integrity -f json -o integrity-report.json
```

This checks:
- SHA256 hashes against npm/PyPI registries
- SLSA provenance attestations
- SRI (Subresource Integrity) values

### 8. Scan History for Audit Trail

Save every scan for historical tracking:

```bash
# Save scan with timestamp
agent-bom scan [your flags] --enrich --save -f json -o scan-$(date +%Y%m%d).json
```

Saved scans go to `~/.agent-bom/history/` and can be diffed:

```bash
agent-bom scan [your flags] --enrich --baseline scan-20260101.json -f json -o current.json
```

### 9. Prometheus / OTLP Metrics

Push scan metrics to monitoring systems:

```bash
# Prometheus Pushgateway
agent-bom scan [your flags] --enrich --push-gateway http://prometheus:9091

# OpenTelemetry collector
agent-bom scan [your flags] --enrich --otel-endpoint http://collector:4318
```

## Compliance Mapping

| Requirement | agent-bom Output |
|-------------|-----------------|
| EU AI Act — AI system inventory | AI-BOM JSON (`document_type: "AI-BOM"`) |
| NIST AI RMF — risk assessment | Threat framework summary + blast radius |
| SOC 2 — vulnerability management | SARIF + scan history + remediation plan |
| ISO 27001 — asset inventory | CycloneDX / SPDX with dependency graph |
| OWASP Top 10 for LLMs | Per-finding OWASP LLM tags |
| FedRAMP — continuous monitoring | Prometheus/OTLP metrics + scan history |

## Outputs

| Artifact | Format | Audience |
|----------|--------|----------|
| `ai-bom.cdx.json` | CycloneDX 1.6 | SBOM consumers, compliance tools |
| `ai-bom.spdx.json` | SPDX 3.0 | ISO auditors |
| `results.sarif` | SARIF | GitHub Security, SAST tools |
| `report.json` | AI-BOM JSON | Programmatic analysis |
| `report.html` | HTML | Management, security team |
| Scan history | JSON | Audit trail |
| Prometheus metrics | OpenMetrics | Monitoring dashboards |
