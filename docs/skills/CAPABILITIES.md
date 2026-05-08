# Skill Capability Contract

Bundled skills are executable product surfaces. Each skill must declare the
minimum capabilities it needs before it can be promoted across CLI, MCP,
runtime proxy, dashboard, or Snowflake Native App paths.

## Required keys

| Key | Meaning |
|---|---|
| `read_findings` | Reads agent-bom findings, vulnerability evidence, SARIF, SBOM, or remediation records. |
| `read_inventory` | Reads agent, package, MCP server, cloud, repository, or infrastructure inventory. |
| `read_audit_log` | Reads prior audit, governance, policy, or runtime event records. |
| `write_findings` | Creates or mutates agent-bom findings, suppressions, comments, export records, or pushed evidence. |
| `outbound_http` | Calls external services, registries, APIs, web pages, or enrichment feeds. |
| `shell_exec` | Runs local shell commands, package managers, scanners, cloud CLIs, or container commands. |

Use `false` instead of omitting a denied capability. Every key must be present
so sandbox policy generation can distinguish reviewed denial from incomplete
metadata.

## Example

```yaml
capabilities:
  read_findings: true
  read_inventory: true
  read_audit_log: false
  write_findings: false
  outbound_http: true
  shell_exec: false
```

## Snowflake Native App readiness

Snowflake and other customer-controlled runtime paths need a static capability
boundary before invocation:

- Read capabilities map to the evidence tables, views, and API resources a
  skill may inspect.
- Write capabilities must stay disabled unless the skill is an explicit,
  human-approved remediation or evidence publishing workflow.
- Network and shell capabilities must match documented endpoints, binaries,
  credential boundaries, and audit records.
- Marketplace or Native App packaging must never depend on hidden local state
  or undeclared binaries.

## Audit behavior

`agent-bom` emits low-severity metadata findings when a skill has no capability
block or omits required keys. The finding is intentionally low severity today:
it does not block existing scans, but it gives release reviewers concrete
evidence before promoting a skill into sandboxed or customer-hosted deployment
lanes.
