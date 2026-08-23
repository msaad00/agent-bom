# Govern agent-bom with agent-bom

The `agent_bom_operator` runtime blueprint and `self-governance` gateway policy
are the reference path for routing an operator agent through the same controls
used for customer workloads. They are opt-in: installing agent-bom does not
silently intercept developer tools.

## First command → evidence → next step

Start in audit mode so risky calls warn while safe read, scan, graph, and audit
operations continue:

```bash
agent-bom gateway init-policy \
  --template self-governance \
  --mode audit \
  --output self-governance.json

agent-bom gateway serve \
  --policy self-governance.json \
  --upstreams deploy/helm/agent-bom/examples/gateway-upstreams.example.yaml
```

The gateway records redaction-safe decisions with actor/profile, target/tool,
policy, reason, trace, and durable event identifiers. Review them in **Runtime →
Live Feed**, `GET /v1/gateway/feed`, and the tenant-scoped audit surface. Raw
arguments, results, prompts, and credential values are not persisted.

After reviewing warnings, render the same policy in enforce mode. A safe scanner
or graph read is allowed; dangerous execution, secret-path access, and unknown
egress are blocked and audited:

```bash
agent-bom gateway init-policy \
  --template self-governance \
  --mode enforce \
  --output self-governance.json
```

For a managed non-loopback deployment, bind the caller identity to an MCP client
assignment whose `profile_id` is `agent_bom_operator`, enable gateway profile
enforcement, and use the shared Postgres control-plane store. Unknown, revoked,
expired, cross-tenant, under-scoped, and out-of-contract callers fail closed.

The deployment's own configuration posture remains a separate evidence surface:

```bash
agent-bom self-audit
curl -H "Authorization: Bearer $AGENT_BOM_TOKEN" https://agent-bom.example/v1/self-posture
```

The dashboard **Self-audit** page reads the same API result. Unknown runtime or
database state remains `unknown`; it is never converted into a passing control.

MCP operators can request the same posture and durable activity without adding
another tool:

```text
gateway_status(include_activity=true, include_self_posture=true)
```

When activity is paged, pass the returned `activity.next_cursor` back as
`activity_cursor`. Cursor expiry is explicit; it never silently restarts at the
newest event.
