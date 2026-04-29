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

## Skill-Mediated Handoff

For AI-agent mediated discovery, use the bundled
`integrations/openclaw/discover-aws/SKILL.md` workflow. It invokes the same
adapter with `--source aws-skill-invoked --discovery-method skill_invoked_pull`
so downstream findings preserve that the AWS API call happened inside the
operator's agent environment, not inside agent-bom.

The adapters keep useful scan context such as package PURLs, cloud metadata,
and declared read permissions, while recursively redacting sensitive
metadata and environment values before writing the inventory file.
