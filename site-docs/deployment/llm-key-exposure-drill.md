# LLM Key Exposure Drill

Use this runbook when an AI assistant, copied shell command, MCP server, or
developer workstation may have exposed OpenAI, Anthropic, Bedrock, Vertex AI,
Azure OpenAI, or other LLM credentials.

The goal is not to prove the breach from agent-bom alone. The goal is to map
where keys are referenced, which agents and MCP servers can reach them, which
runtime paths could have moved them, and what evidence should drive rotation.

## First 30 Minutes

| Step | Command | Artifact | Decision |
|---|---|---|---|
| Inventory local agent/MCP exposure | `agent-bom agents -p . -f json -o agent-bom-agents.json` | agents, MCP servers, packages, exposed credential env-var names | Which local configs reference AI provider credentials? |
| Scan instruction files | `agent-bom skills scan . -f json -o agent-bom-skills.json` | risky instructions, command execution patterns, credential references | Did repo instructions encourage unsafe command execution or secret access? |
| Export review packet | `agent-bom agents -p . -f html -o agent-bom-llm-key-review.html` | human-readable blast-radius packet | Which teams need to review and rotate first? |
| Preserve runtime evidence if present | collect proxy/gateway audit JSONL and trace IDs | audit decisions, tool calls, relay metadata | Was this a live tool-call path or a static exposure path? |

Do not wait for perfect attribution before rotating active production keys. Use
agent-bom to reduce the unknowns: owner, environment, agent, MCP server, tool,
package, and workload reachability.

## Rotation Scope Checklist

| Scope | What to check | Evidence source |
|---|---|---|
| Developer laptops | Claude/Cursor/Windsurf/Codex/Cortex config, MCP server env names, shell profiles | `agent-bom agents`, endpoint fleet sync |
| CI/CD | repository secrets, Actions variables, SARIF upload token permissions, build logs | GitHub audit, `agent-bom-results.sarif`, CI artifacts |
| Runtime MCP paths | stdio proxy audit, gateway relay, policy decisions, undeclared tool blocks | proxy/gateway JSONL, control-plane runtime evidence |
| Cloud and model platforms | Bedrock/Vertex/Azure/OpenAI/Anthropic key owners, IAM role scope, model invoke permissions | provider console, cloud inventory scans |
| Applications | LangChain, CrewAI, OpenAI/Anthropic SDK usage, Shield decisions | AI inventory scan, application logs |
| Warehouses and observability | Snowflake, Databricks, W&B, MLflow, Langfuse/LangSmith references | read-only provider inventory, config review |

## What Agent-BOM Can Prove

- Which MCP clients, servers, package dependencies, tools, and credential
  environment variable names are visible in scanned configs.
- Which instruction files contain risky command, credential, exfiltration, or
  trust-bypass patterns.
- Which vulnerable packages sit inside the same MCP server or agent path as an
  LLM credential reference.
- Which runtime proxy or gateway path emitted an audit event, block, or alert.
- Which evidence is safe durable Tier-A metadata versus replay-only content.

## What It Does Not Prove Alone

- That an attacker actually used a leaked key.
- That every laptop, CI job, or production workload was scanned.
- That a static graph edge is runtime causality.
- That provider-side logs were retained or complete.

Pair agent-bom evidence with provider audit logs, endpoint telemetry, SIEM
events, and key-usage billing records before making incident-scope claims.

## Follow-Up Controls

- Move long-lived provider keys into short-lived workload identity wherever the
  provider supports it.
- Put local stdio MCP servers that touch files, shell, network, or secrets
  behind `agent-bom proxy` when runtime evidence matters.
- Treat proxy containment as a separate setting from proxy audit. `agent-bom
  proxy --no-isolate` gives audit and policy evidence without process
  containment. Container isolation applies to stdio MCP servers when Docker or
  Podman is available and the proxy is given a sandbox image with
  `--sandbox-image` or `AGENT_BOM_MCP_SANDBOX_IMAGE`; production deployments
  should also set `--sandbox-image-pin-policy enforce`.
- Use gateway policy for shared remote MCPs and central tenant audit.
- Do not claim the gateway containerizes remote MCP upstreams. It centralizes
  auth, tenancy, routing, policy decisions, relay metrics, and audit evidence;
  upstream runtime containment remains in the upstream workload or sidecar.
- Keep SARIF and HTML packets attached to the incident record.
- Add the rotation owner, timestamp, and verification command to the release or
  incident notes.
