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

The adapter keeps useful scan context such as package PURLs, cloud metadata,
and declared AWS read permissions, while recursively redacting sensitive
metadata and environment values before writing the inventory file.
