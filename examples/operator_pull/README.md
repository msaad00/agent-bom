# AWS Operator-Pull Inventory Adapter

This reference adapter runs in the operator's environment with the operator's
own ephemeral or tightly scoped AWS credentials. It emits canonical
`agent-bom` inventory JSON locally, so a later `agent-bom` scan can run from a
file without receiving raw cloud credentials.

```bash
python examples/operator_pull/aws_inventory_adapter.py \
  --region us-east-1 \
  --include-lambda \
  --include-eks \
  --output aws-inventory.json

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_PROFILE
agent-bom agents --inventory aws-inventory.json --format json
```

For AI-agent mediated discovery, use the bundled
`integrations/openclaw/discover-aws/SKILL.md` workflow. It invokes the same
adapter with `--source aws-skill-invoked --discovery-method skill_invoked_pull`
so downstream findings preserve that the AWS API call happened inside the
operator's agent environment, not inside agent-bom.

The adapter keeps useful scan context such as package PURLs, cloud metadata,
and declared AWS read permissions, while recursively redacting sensitive
metadata and environment values before writing the inventory file.
