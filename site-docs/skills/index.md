# Skills

agent-bom includes pre-built skill workflows for common security tasks.

Skills are agentic invocation layers over the same `agent-bom` CLI, API, MCP,
normalization, scanning, graph, and export contracts. See
[Agentic Skills Architecture](../architecture/agentic-skills-architecture.md)
for the layered model, subagent delegation rules, and OSV/GHSA guardrails.
The repo also maintains a
[skill capability contract](https://github.com/msaad00/agent-bom/blob/main/docs/skills/CAPABILITIES.md)
for CLI, MCP, sandbox, and Snowflake Native App readiness.

## Readiness Lanes

| Lane | Required evidence | Promotion gate |
|------|-------------------|----------------|
| OSS CLI/API | First command, output artifact, schema or validation path | `agent-bom` smoke plus targeted skill audit |
| MCP / assistant invocation | Same artifact contract plus delegated-agent guardrails | MCP tool listing and strict argument behavior |
| Snowflake Native App | Complete capability map, credential boundary, no hidden local state | Customer-account install path and audit evidence |

| Skill | File | Use case |
|-------|------|----------|
| [AI BOM Generator](https://github.com/msaad00/agent-bom/blob/main/docs/skills/ai-bom-generator.md) | `ai-bom-generator.md` | Generate comprehensive AI supply chain BOMs |
| [Cloud Security Audit](https://github.com/msaad00/agent-bom/blob/main/docs/skills/cloud-security-audit.md) | `cloud-security-audit.md` | Cloud provider security assessment |
| [Compliance Export](https://github.com/msaad00/agent-bom/blob/main/docs/skills/compliance-export.md) | `compliance-export.md` | Export compliance reports for auditors |
| [CSPM AWS](https://github.com/msaad00/agent-bom/blob/main/docs/skills/cspm-aws-benchmark.md) | `cspm-aws-benchmark.md` | AWS CIS benchmark |
| [CSPM Azure](https://github.com/msaad00/agent-bom/blob/main/docs/skills/cspm-azure-benchmark.md) | `cspm-azure-benchmark.md` | Azure security benchmark |
| [CSPM GCP](https://github.com/msaad00/agent-bom/blob/main/docs/skills/cspm-gcp-benchmark.md) | `cspm-gcp-benchmark.md` | GCP security benchmark |
| [AWS Discovery Skill](https://github.com/msaad00/agent-bom/blob/main/integrations/openclaw/discover-aws/SKILL.md) | `integrations/openclaw/discover-aws/SKILL.md` | Standalone AWS inventory discovery with optional agent-bom handoff |
| [Vulnerability Intelligence Skill](https://github.com/msaad00/agent-bom/blob/main/integrations/openclaw/vulnerability-intel/SKILL.md) | `integrations/openclaw/vulnerability-intel/SKILL.md` | Guardrailed OSV/GHSA/NVD/EPSS/KEV advisory lookup through agent-bom evidence paths |
| [Incident Response](https://github.com/msaad00/agent-bom/blob/main/docs/skills/incident-response.md) | `incident-response.md` | CVE incident investigation |
| [MCP Server Review](https://github.com/msaad00/agent-bom/blob/main/docs/skills/mcp-server-review.md) | `mcp-server-review.md` | Pre-install MCP server trust assessment |
| [OWASP LLM Assessment](https://github.com/msaad00/agent-bom/blob/main/docs/skills/owasp-llm-assessment.md) | `owasp-llm-assessment.md` | OWASP LLM Top 10 compliance check |
| [Pre-Deploy Gate](https://github.com/msaad00/agent-bom/blob/main/docs/skills/pre-deploy-gate.md) | `pre-deploy-gate.md` | CI/CD security gate |
