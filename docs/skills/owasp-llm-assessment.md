# OWASP LLM Top 10 Assessment

> Systematic OWASP LLM Top 10 + MITRE ATLAS threat assessment across your AI infrastructure.

## Goal

Assess your AI infrastructure against the [OWASP Top 10 for LLM Applications](https://owasp.org/www-project-top-10-for-large-language-model-applications/) and [MITRE ATLAS](https://atlas.mitre.org/) adversarial ML framework. Identify which threat categories apply, quantify exposure per category, and prioritize remediation.

## Prerequisites

```bash
pip install agent-bom
# Install cloud extras for your environment:
pip install 'agent-bom[cloud]'  # All providers
```

## Threat Framework Reference

### OWASP LLM Top 10

| Code | Name | agent-bom triggers when |
|------|------|------------------------|
| **LLM01** | Prompt Injection | (manual review — agent-bom flags injection surfaces) |
| **LLM02** | Insecure Output Handling | Tool with shell/exec semantics |
| **LLM04** | Model Denial of Service | AI framework + HIGH+ CVE |
| **LLM05** | Supply Chain Vulnerabilities | Any package CVE (always) |
| **LLM06** | Sensitive Information Disclosure | Credential env var exposed alongside CVE |
| **LLM07** | Insecure Plugin Design | Tool that reads files or prompts |
| **LLM08** | Excessive Agency | Server with >5 tools + CRITICAL/HIGH CVE |

### MITRE ATLAS

| Technique | Name | agent-bom triggers when |
|-----------|------|------------------------|
| **AML.T0010** | ML Supply Chain Compromise | Any package CVE (always) |
| **AML.T0020** | Poison Training Data | AI framework + HIGH+ CVE |
| **AML.T0043** | Craft Adversarial Data | Tools with shell/exec capability |
| **AML.T0051** | LLM Prompt Injection | Tools can access prompts/context |
| **AML.T0056** | LLM Meta Prompt Extraction | Tools can read files |
| **AML.T0058** | Agent Context Poisoning | AI framework + creds + HIGH+ |
| **AML.T0061** | LLM Jailbreak | >3 tools reachable through compromised path |
| **AML.T0062** | Credential Theft via LLM | Credentials exposed alongside vulnerability |

## Steps

### 1. Baseline Assessment

Run a full scan with enrichment to establish threat framework baseline:

```bash
agent-bom scan \
  [your discovery flags] \
  --enrich \
  -f json -o owasp-assessment.json
```

### 2. Extract Threat Framework Summary

```bash
python3 -c "
import json
report = json.load(open('owasp-assessment.json'))
summary = report.get('threat_framework_summary', {})

print('OWASP LLM Top 10 Coverage')
print('=' * 50)
triggered = 0
for item in summary.get('owasp_llm_top10', []):
    if item['triggered']:
        triggered += 1
        print(f\"  [{item['code']}] {item['name']}: {item['findings']} finding(s)\")
    else:
        print(f\"  [{item['code']}] {item['name']}: -\")
print(f\"\nTriggered: {triggered}/10\")

print('\nMITRE ATLAS Coverage')
print('=' * 50)
triggered = 0
for item in summary.get('mitre_atlas', []):
    if item['triggered']:
        triggered += 1
        print(f\"  [{item['technique_id']}] {item['name']}: {item['findings']} finding(s)\")
print(f\"Triggered: {triggered}/{len(summary.get('mitre_atlas', []))}\")
"
```

### 3. Per-Category Deep Dive

For each triggered category, drill into the specific findings:

#### LLM05 — Supply Chain Vulnerabilities

This is triggered by any CVE. Focus on:
- Packages with CRITICAL/HIGH CVEs
- Packages in CISA KEV (actively exploited)
- Packages with EPSS > 0.5

```bash
# Fail if supply chain vulnerabilities exist at HIGH+
agent-bom scan [your flags] --enrich --fail-on-severity high -q
```

#### LLM06 — Sensitive Information Disclosure

Triggered when credentials are exposed alongside CVEs:

```bash
python3 -c "
import json
report = json.load(open('owasp-assessment.json'))
for v in report.get('vulnerabilities', []):
    tags = v.get('owasp_tags', [])
    if 'LLM06' in [t.get('code') for t in tags]:
        print(f\"  {v['id']}: {v.get('summary', '')}\")
        br = v.get('blast_radius', {})
        for cred in br.get('credentials', []):
            print(f\"    Credential: {cred}\")
"
```

**Remediation**: Rotate exposed credentials, patch vulnerable packages, minimize credential scope.

#### LLM08 — Excessive Agency

Triggered for servers with >5 tools + CRITICAL/HIGH CVEs:

Review tool counts per server. Consider:
- Splitting servers with too many tools
- Removing tools that aren't actively used
- Using policy rules to enforce tool limits

```json
{"id": "limit-tools", "min_tools": 6, "action": "warn"}
```

#### LLM02 — Insecure Output Handling

Triggered for shell/exec tools. These are the highest-risk tools:

- `execute_command`, `run_shell`, `bash`
- `query_database`, `execute_sql`

**Remediation**: Remove shell tools if not needed. If needed, sandbox them (e.g., via ToolHive containers).

### 4. Cloud-Specific Threat Assessment

#### AWS

```bash
agent-bom scan --aws --aws-region us-east-1 \
  --aws-include-lambda --aws-include-eks --aws-include-step-functions \
  --enrich -f json -o owasp-aws.json
```

AWS-specific risks:
- Lambda functions with AI runtimes — LLM05 (dependency vulnerabilities)
- Bedrock agents with broad IAM — LLM08 (excessive agency)
- Step Functions orchestrating Lambda + Bedrock — LLM06 (credential chains)

#### Snowflake

```bash
agent-bom scan --snowflake --enrich -f json -o owasp-snowflake.json
```

Snowflake-specific risks:
- `SYSTEM_EXECUTE_SQL` MCP tools — LLM02 (insecure output → SQL execution)
- Cortex Agents with broad permissions — LLM08 (excessive agency)
- Query history reveals CREATE MCP SERVER — audit trail for shadow IT

#### Azure / GCP / Databricks

```bash
agent-bom scan --azure --gcp --databricks --enrich -f json -o owasp-multicloud.json
```

### 5. Generate Visual Report

```bash
agent-bom scan [your flags] --enrich -f html -o owasp-report.html
```

The HTML dashboard includes:
- Two-column threat matrix (OWASP + ATLAS)
- Hit/miss indicators per category
- Finding counts per category
- Severity donut chart
- Blast radius table

### 6. Remediation Priorities

Based on threat framework analysis, prioritize:

1. **LLM02 + AML.T0043** (shell tools) — highest individual risk
2. **LLM06 + AML.T0062** (credential exposure) — enables lateral movement
3. **LLM08 + AML.T0061** (excessive agency) — amplifies any other vulnerability
4. **LLM05 + AML.T0010** (supply chain) — address by patching packages
5. **LLM07 + AML.T0056** (file/prompt access) — data exfiltration risk

### 7. Track Progress

Save and diff to track threat framework improvement:

```bash
# Save baseline
agent-bom scan [your flags] --enrich --save -f json -o baseline.json

# After remediation
agent-bom scan [your flags] --enrich --baseline baseline.json -f json -o improved.json
```

Compare triggered category counts between baseline and current.

## Assessment Summary Template

```
OWASP LLM Top 10 Assessment — [Organization] — [Date]
======================================================

Categories Triggered: X/10
Total Findings: N

Priority Remediations:
1. [LLM02] Remove/sandbox shell tools on [server-name]
2. [LLM06] Rotate [credential-name], patch [package] to [version]
3. [LLM08] Split [server-name] (12 tools) into focused servers
4. [LLM05] Upgrade [package] to clear N CVEs

MITRE ATLAS Techniques Triggered: Y/8
Highest-risk technique: [technique-id] — [description]

Next Assessment: [Date + 30 days]
```
