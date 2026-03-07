# MCP Tools Reference

agent-bom exposes 20 tools via its MCP server.

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
verify(package="agent-bom@0.59.1")
```

### skill_trust
Assess the trust level of a SKILL.md file (5-category analysis).

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

## Resources

| URI | Description |
|-----|-------------|
| `registry://servers` | Browse the full MCP server security metadata registry |
| `policy://template` | Default security policy template |
