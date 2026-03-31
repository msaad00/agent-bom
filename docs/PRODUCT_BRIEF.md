# Product Brief

`agent-bom` is an open security platform for agentic infrastructure.

It is built around a simple thesis: security and visibility for agentic infrastructure should be open, transparent, and accessible, not reserved for teams with enterprise budgets.

Traditional scanners often stop at `CVE -> package`. `agent-bom` follows the operational path further: package risk into MCP servers, agents, credentials, tools, runtime behavior, and trust posture. That is the core product value.

Current repo-derived counts live in [PRODUCT_METRICS.md](PRODUCT_METRICS.md). This brief intentionally keeps volatile metrics out of the main narrative.

## Durable thesis

- Agent security is not just software composition analysis. It is context across packages, MCP servers, agent configuration, credentials, tools, and runtime behavior.
- Security for agentic infrastructure should be inspectable and explainable. Findings should show blast radius, not just raw package IDs.
- Strong security and visibility should be available to individual developers and small teams, not only to enterprises with large budgets and long procurement cycles.

## Stable capability brief

### Discovery

`agent-bom` discovers agent and MCP environments from local config, project manifests, container images, cloud surfaces, and supporting config files. It understands mainstream MCP client setups, not just generic manifests.

### Scanning

The scanner covers package risk, malicious or suspicious package indicators, container layers, IaC, cloud AI surfaces, secrets, and instruction or skill files. The goal is not only to inventory components, but to connect them to the environments where they run.

### Blast radius

Blast radius is the product center of gravity. `agent-bom` connects vulnerabilities to packages, MCP servers, agents, credential exposure, and reachable tools. Impact is CWE-aware so the reported consequences match the weakness class instead of inflating every issue into full compromise.

### Trust and policy

`agent-bom` scores trust with evidence, not a black-box label. It combines package and registry posture, capability risk, drift, exposed credentials, and related supply-chain signals. Policy and compliance layers can then act on those findings with clearer context.

### Runtime protection

The runtime story has two levels:

- a lighter MCP proxy path that inspects live JSON-RPC traffic inline
- a broader runtime protection engine used for deeper protection workflows

The wording matters. The proxy and the broader runtime engine are related, but they are not the same path and should not be described as the same detector surface.

### Skills and instruction files

`agent-bom` treats skill and instruction files as part of the agent attack surface. It scans common instruction surfaces, builds stable bundle identity for review, and is moving toward stronger trust verdicts and richer behavioral analysis.

### Compliance and evidence

Findings can be mapped into compliance and governance views, but the product should present that as evidence generation and control mapping, not as a substitute for a real security program.

### Cloud, containers, and infrastructure

The product is broader than MCP alone. It includes cloud posture, container scanning, IaC, and fleet or API surfaces. That breadth matters because agent risk rarely stops at a single config file.

## Positioning

Good external phrasing:

- Open security platform for agentic infrastructure
- Context-aware security for agents, MCP, runtime, and AI supply chain
- Blast radius from package risk to agents, credentials, tools, and runtime

Avoid:

- absolute claims like "nobody else" or "no competitor"
- hand-counted metrics in the main narrative
- mixing historical audit snapshots with current product truth

When comparing the product, prefer language like:

- "unusually complete for an open tool"
- "one of the only open tools combining discovery, blast radius, runtime, and MCP-aware trust in one system"

## References

- [README](../README.md)
- [Product metrics](PRODUCT_METRICS.md)
- [Claude Desktop / Claude Code integration](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code integration](CORTEX_CODE.md)
- [MCP server mode](MCP_SERVER.md)
- [Runtime monitoring and proxy](RUNTIME_MONITORING.md)
- [MCP security model](MCP_SECURITY_MODEL.md)
- [Architecture](ARCHITECTURE.md)
- [Threat model](THREAT_MODEL.md)
