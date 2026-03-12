# MCP Tools Reference

agent-bom exposes 31 tools via its MCP server.

## Tools

### scan
Full discovery + vulnerability scan pipeline. Auto-discovers MCP clients, extracts servers and packages, scans for CVEs, computes blast radius.

### check
Check a single package for vulnerabilities.
```
check(package="langchain", ecosystem="pypi")
```

### blast_radius
Map the full impact chain of a CVE across agents, servers, credentials, and tools.
```
blast_radius(cve_id="CVE-2024-21538")
```

### registry_lookup
Look up an MCP server in the 427+ server security metadata registry.
```
registry_lookup(server_name="brave-search")
```

### compliance
Run compliance framework checks (OWASP, MITRE ATLAS, EU AI Act, NIST, CIS, SOC 2, ISO 27001).
```
compliance(frameworks=["owasp-llm", "eu-ai-act"])
```

### remediate
Generate a prioritized remediation plan for discovered vulnerabilities.

### verify
Package integrity check with Sigstore signature and SLSA provenance verification.
```
verify(package="agent-bom@0.60.0")
```

### skill_trust
Audit an AI instruction file (SKILL.md, CLAUDE.md, .cursorrules, AGENTS.md) for supply chain risks, malicious behavioral patterns, and trust level.

Runs 17 behavioral risk patterns (credential file access, confirmation bypass, messaging/impersonation, voice/telephony, filesystem exfiltration, data exfiltration, and more) plus 5-category structural trust assessment:

| Category | Checks |
|----------|--------|
| Purpose & Capability | name/description consistency, binary/network scope |
| Instruction Scope | file reads bounded, data handling documented |
| Install Mechanism | install source, Sigstore signature, provenance |
| Credentials | proportionate, scoped, documented env vars |
| Persistence & Privilege | no persistence, no escalation, no telemetry |

Returns a verdict (`benign` / `suspicious` / `malicious`), confidence level, per-category results, and all findings with severity and recommendations.

```
skill_trust(skill_content="<paste full file content>")
# → {
#     "verdict": "suspicious",
#     "confidence": "high",
#     "categories": [
#       { "name": "Install Mechanism", "level": "fail", "summary": "Unverified install source" },
#       ...
#     ],
#     "findings": [
#       { "severity": "critical", "title": "Credential/secret file access", "detail": "..." },
#       ...
#     ]
#   }
```

### generate_sbom
Generate an SBOM in CycloneDX or SPDX format.
```
generate_sbom(format="cyclonedx")
```

### policy_check
Evaluate scan results against a security policy file.

### diff
Compare two scan reports showing new, resolved, and persistent findings.

### marketplace_check
Pre-install trust check combining registry lookup with integrity verification.

### code_scan
SAST scanning via Semgrep with CWE-based compliance mapping.

### where
Show all MCP client config discovery paths and what was found.

### inventory
List all discovered agents, servers, and packages.

### context_graph
Agent context graph with BFS lateral movement analysis.

### analytics_query
Query vulnerability trends and posture history from ClickHouse.

### cis_benchmark
Run CIS benchmark checks against AWS or Snowflake accounts.
```
cis_benchmark(provider="aws")
```

### fleet_scan
Batch registry lookup + risk scoring for MCP server inventories.
```
fleet_scan(servers=["brave-search", "filesystem", "postgres"])
```

### runtime_correlate
Cross-reference runtime audit logs with CVE findings for risk amplification.

### vector_db_scan
Probe Qdrant, Weaviate, Chroma, and Milvus instances for authentication misconfigurations and exposure.
```
vector_db_scan()
```

### aisvs_benchmark
Run OWASP AISVS v1.0 compliance checks — 9 AI security verification checks across model, data, and inference layers.
```
aisvs_benchmark()
```

### gpu_infra_scan
Scan GPU and AI compute infrastructure — Docker GPU containers, Kubernetes GPU nodes, DCGM unauthenticated endpoint detection.
```
gpu_infra_scan()
```

### dataset_card_scan
Scan dataset cards (Hugging Face, custom) for supply chain risks, license issues, and data provenance gaps.
```
dataset_card_scan(path="/path/to/dataset_card.md")
```

### training_pipeline_scan
Scan training pipeline configurations for security risks — untrusted data sources, insecure checkpoints, credential exposure.
```
training_pipeline_scan(path="/path/to/training_config.yaml")
```

### browser_extension_scan
Scan browser extensions for MCP and AI-related risks — nativeMessaging, broad host permissions, AI assistant domain access.
```
browser_extension_scan()
```

### model_provenance_scan
Verify model provenance and integrity — check Sigstore signatures, SLSA provenance, and supply chain attestations.
```
model_provenance_scan(model="org/model-name")
```

### prompt_scan
Scan prompts for injection patterns, exfiltration attempts, and manipulation techniques.
```
prompt_scan(prompt="<prompt text>")
```

### model_file_scan
Scan model files (ONNX, pickle, SafeTensors, etc.) for embedded threats, unsafe deserialization, and hidden payloads.
```
model_file_scan(path="/path/to/model.onnx")
```

### license_compliance_scan
SPDX license compliance and compatibility checks — full SPDX catalog support, network-copyleft detection, license conflict identification.
```
license_compliance_scan()
```

## Resources

| URI | Description |
|-----|-------------|
| `registry://servers` | Browse the full MCP server security metadata registry |
| `policy://template` | Default security policy template |
