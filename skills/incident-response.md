# Incident Response

> Given a CVE or security advisory, find every affected AI agent, map blast radius, and generate a remediation plan.

## Goal

When a new CVE drops or a security advisory is published, quickly determine: **which MCP servers have affected packages, what credentials are exposed, which tools an attacker can reach, and what to fix first.**

## Prerequisites

```bash
pip install agent-bom
# Install cloud extras for the providers in your environment
```

## Steps

### 1. Identify the CVE

Start with the CVE ID (e.g., `CVE-2025-1234`) or package name + version.

Check if the package is in your inventory:

```bash
agent-bom check <package>@<version> -e <ecosystem>
# Example: agent-bom check express@4.17.1 -e npm
```

This immediately tells you if the package has known vulnerabilities without a full scan.

### 2. Full Environment Scan

Run a scan across all discovery sources to find every instance of the affected package:

```bash
# Local agents + containers + K8s + cloud
agent-bom scan \
  --aws --aws-region us-east-1 --aws-include-lambda --aws-include-eks \
  --snowflake \
  --k8s --all-namespaces \
  --enrich \
  -f json -o incident-scan.json
```

### 3. Blast Radius Analysis

The JSON output includes blast radius for every vulnerability. Search for the specific CVE:

```bash
# Extract blast radius for the target CVE
python3 -c "
import json
report = json.load(open('incident-scan.json'))
for v in report.get('vulnerabilities', []):
    if '$CVE_ID' in v.get('aliases', []) or v.get('id') == '$CVE_ID':
        print(json.dumps(v, indent=2))
"
```

The blast radius shows:
- **Affected agents** — which AI agents use the vulnerable package
- **Exposed credentials** — which API keys/tokens are reachable
- **Reachable tools** — which MCP tools an attacker can access
- **Impact percentage** — fraction of total inventory at risk

### 4. Threat Framework Classification

Check which OWASP LLM + MITRE ATLAS categories apply:

- **LLM05 + AML.T0010** — Supply chain vulnerability (always triggered)
- **LLM06 + AML.T0062** — If credentials are exposed alongside the CVE
- **LLM08 + AML.T0061** — If >5 tools reachable through the compromised path
- **LLM02 + AML.T0043** — If shell/exec tools are in the blast radius

### 5. Prioritize by Risk

Sort affected assets by urgency:

1. **CISA KEV listed** — actively exploited, patch immediately
2. **EPSS > 0.5** — high probability of exploitation within 30 days
3. **Credentials in blast radius** — attacker can pivot to other systems
4. **Shell/exec tools reachable** — remote code execution path exists
5. **High CVSS + wide blast radius** — large impact surface

### 6. Generate Remediation Plan

The HTML report includes the enterprise remediation plan with named assets:

```bash
agent-bom scan [your flags] --enrich -f html -o incident-report.html
```

Each remediation entry shows:
- Upgrade path (e.g., `express 4.17.1 -> 4.21.0`)
- How many vulnerabilities the upgrade clears
- Which agents, credentials, and tools are protected
- Which OWASP + MITRE categories are mitigated
- Risk narrative: what happens if you don't fix it

### 7. Verify Fix

After applying the fix, re-scan and diff against the incident baseline:

```bash
agent-bom scan [your flags] --enrich --baseline incident-scan.json -f json -o post-fix.json
```

The diff shows which vulnerabilities were resolved and any new ones introduced.

**Decision point**: If the fix introduces new dependencies, verify they don't bring new CVEs. The baseline diff highlights "new vulnerabilities" automatically.

### 8. Export for Stakeholders

```bash
# For security team — SARIF for GitHub Security tab
agent-bom scan [your flags] --enrich -f sarif -o incident.sarif

# For compliance — CycloneDX SBOM
agent-bom scan [your flags] --enrich -f cyclonedx -o incident.cdx.json

# For management — HTML dashboard
agent-bom scan [your flags] --enrich -f html -o incident-report.html
```

## Triage Decision Tree

```
CVE Reported
    │
    ├─ Is it in CISA KEV? ─── YES ──→ Patch within 24h
    │                          NO
    │
    ├─ EPSS > 0.5? ────────── YES ──→ Patch within 48h
    │                          NO
    │
    ├─ Credentials in blast   YES ──→ Rotate credentials + patch within 72h
    │   radius?                NO
    │
    ├─ Shell/exec tools       YES ──→ Patch within 72h + review tool permissions
    │   reachable?             NO
    │
    ├─ CVSS >= 9.0?  ──────── YES ──→ Patch within 1 week
    │                          NO
    │
    └─ Schedule in next sprint
```

## Outputs

| Artifact | Purpose |
|----------|---------|
| `incident-scan.json` | Full scan baseline at time of incident |
| `incident-report.html` | Visual dashboard for triage meeting |
| `incident.sarif` | GitHub Security tab upload |
| `post-fix.json` | Verification scan after remediation |
