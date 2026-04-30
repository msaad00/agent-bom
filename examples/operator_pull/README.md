# Operator-Pull Inventory Adapters

These reference adapters run in the operator's environment with the operator's
own ephemeral or tightly scoped cloud credentials. They emit canonical
`agent-bom` inventory JSON locally. That is useful by itself: the operator can
inspect, archive, or route the JSON to an internal CMDB without running an
agent-bom scan.

Passing the inventory to agent-bom is an explicit handoff. Use `agent-bom agents
--inventory ...` only when you want agent-bom findings, graph, policy, and
exports from the discovered assets.

## AWS

```bash
python examples/operator_pull/aws_inventory_adapter.py \
  --region us-east-1 \
  --include-lambda \
  --include-eks \
  --output aws-inventory.json

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
agent-bom agents --inventory aws-inventory.json --format json
```

## Azure

```bash
python examples/operator_pull/azure_inventory_adapter.py \
  --subscription-id 00000000-0000-0000-0000-000000000000 \
  --resource-group ai-platform \
  --output azure-inventory.json

agent-bom agents --inventory azure-inventory.json --format json
```

## GCP

```bash
python examples/operator_pull/gcp_inventory_adapter.py \
  --project my-gcp-project \
  --region us-central1 \
  --output gcp-inventory.json

agent-bom agents --inventory gcp-inventory.json --format json
```

## Snowflake

```bash
python examples/operator_pull/snowflake_inventory_adapter.py \
  --account my-org-my-account \
  --authenticator externalbrowser \
  --database AI_PLATFORM \
  --schema PUBLIC \
  --output snowflake-inventory.json

unset SNOWFLAKE_PASSWORD SNOWFLAKE_TOKEN SNOWFLAKE_PRIVATE_KEY_PATH
agent-bom agents --inventory snowflake-inventory.json --format json
```

## Skill-Mediated Handoff

For AI-agent mediated discovery, use the bundled
`integrations/openclaw/discover-aws/SKILL.md` workflow. The skill is
discover-only by default: it invokes the same adapter with
`--source aws-skill-invoked --discovery-method skill_invoked_pull`, writes
canonical inventory JSON, and stops. Scanning or pushing that inventory into an
agent-bom workflow is a separate operator-approved handoff.

That keeps the discovery primitive useful on its own. Teams can inspect the
JSON, archive it, route it to a CMDB, or pass it to `agent-bom agents
--inventory ...` only when they want findings, graph, policy, and exports.

The adapters keep useful scan context such as package PURLs, cloud metadata,
and declared read permissions, while recursively redacting sensitive
metadata and environment values before writing the inventory file.
