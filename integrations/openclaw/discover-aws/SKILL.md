---
name: agent-bom-discover-aws
description: >-
  Discover AWS-hosted AI agent and MCP-relevant assets from the operator's
  environment, emit canonical agent-bom inventory JSON, and scan it without
  giving agent-bom long-lived cloud credentials. Use when a user asks to
  inventory AWS Bedrock, ECS, SageMaker, Lambda, EKS, Step Functions, EC2, or
  agentic AWS infrastructure as canonical inventory. Passing that inventory
  to agent-bom is optional and operator-chosen.
version: 0.84.5
license: Apache-2.0
compatibility: >-
  Requires Python 3.11+, agent-bom installed from this repository or PyPI, and
  operator-controlled AWS credentials from AWS SSO, WebIdentity, or STS. Prefer
  short-lived credentials and read-only IAM policy scope.
metadata:
  author: msaad00
  homepage: https://github.com/msaad00/agent-bom
  source: https://github.com/msaad00/agent-bom
  pypi: https://pypi.org/project/agent-bom/
  openclaw:
    requires:
      bins:
        - python
      env: []
      credentials: aws-read-only
    credential_policy: "Use the operator's existing AWS SDK credential chain. Prefer AWS SSO, WebIdentity, or STS assumed-role credentials. Do not ask users to paste access keys. Do not print credential values."
    optional_env:
      - AWS_PROFILE
      - AWS_REGION
      - AWS_DEFAULT_REGION
    optional_bins: []
    emoji: "\U0001F50E"
    homepage: https://github.com/msaad00/agent-bom
    source: https://github.com/msaad00/agent-bom
    license: Apache-2.0
    os:
      - darwin
      - linux
      - windows
    credential_handling: "Credentials stay in the operator environment. The skill invokes the AWS SDK locally and writes canonical inventory JSON with source_type=skill_invoked_pull. agent-bom receives sanitized inventory only when the operator explicitly scans or pushes that inventory."
    data_flow: "Operator AWS account -> read-only AWS SDK calls -> canonical inventory JSON -> agent-bom inventory scan. No agent-bom-hosted service is required. Values matching credential patterns are redacted before persistence/export."
    file_reads: []
    file_writes:
      - "operator-selected inventory JSON output path"
    network_endpoints:
      - url: "https://sts.amazonaws.com"
        purpose: "Caller identity and assumed-role context"
        auth: true
      - url: "https://bedrock-agent.{region}.amazonaws.com"
        purpose: "Bedrock agent inventory"
        auth: true
      - url: "https://ecs.{region}.amazonaws.com"
        purpose: "ECS workload inventory when enabled"
        auth: true
      - url: "https://sagemaker.{region}.amazonaws.com"
        purpose: "SageMaker inventory when enabled"
        auth: true
      - url: "https://lambda.{region}.amazonaws.com"
        purpose: "Lambda inventory when enabled"
        auth: true
      - url: "https://eks.{region}.amazonaws.com"
        purpose: "EKS inventory when enabled"
        auth: true
      - url: "https://states.{region}.amazonaws.com"
        purpose: "Step Functions inventory when enabled"
        auth: true
      - url: "https://ec2.{region}.amazonaws.com"
        purpose: "EC2 inventory when enabled"
        auth: true
    telemetry: false
    persistence: false
    privilege_escalation: false
    always: false
    autonomous_invocation: restricted
---

# agent-bom-discover-aws

Use this skill to collect AWS AI and workload inventory from the operator's
environment as canonical inventory. The skill is discover-only by default:
write schema-valid JSON to an operator-selected path and stop. Run
`agent-bom` only when the operator explicitly wants findings, graph, policy,
or exports from that inventory.

## Guardrails

- Use only operator-approved AWS profiles, roles, or short-lived STS sessions.
- Prefer read-only IAM actions listed by `agent-bom trust` or
  `/v1/discovery/providers`.
- Do not request or display raw `AWS_ACCESS_KEY_ID`,
  `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, or bearer tokens.
- Do not modify AWS resources. This workflow is discovery-only.
- Write inventory only to a path the operator chose.
- Treat AI-generated prose as non-authoritative; only the schema-validated
  inventory JSON is evidence.

## Modes

| Mode | What happens | Data boundary |
|------|--------------|---------------|
| `discover-only` | Emit canonical inventory JSON and stop | No agent-bom scan or API handoff |
| `scan-local` | Run `agent-bom agents --inventory ...` on the generated file | Local handoff into the scanner |
| `export` | Write JSON/SARIF or another operator-selected output | Local output only unless the operator routes it elsewhere |

Use `discover-only` unless the operator asks for scan results or an export.

## Workflow

1. Confirm the AWS account/region/profile and intended services.
2. Generate inventory with the repository adapter and stop:

```bash
python examples/operator_pull/aws_inventory_adapter.py \
  --region us-east-1 \
  --profile readonly-audit \
  --source aws-skill-invoked \
  --discovery-method skill_invoked_pull \
  --output aws-inventory.json
```

3. If the operator asks for findings, scan the generated inventory locally:

```bash
agent-bom agents --inventory aws-inventory.json
```

4. If the operator asks for an export, write it to an operator-selected path:

```bash
agent-bom agents --inventory aws-inventory.json --format json --output agent-bom-aws-findings.json
```

## Optional Service Flags

Start narrow, then expand deliberately:

```bash
python examples/operator_pull/aws_inventory_adapter.py \
  --region us-east-1 \
  --profile readonly-audit \
  --source aws-skill-invoked \
  --discovery-method skill_invoked_pull \
  --include-ecs \
  --include-lambda \
  --include-eks \
  --output aws-inventory.json
```

Use `--no-include-ecs` or similar flags to disable default services when an
operator wants a smaller scope.

## Evidence Contract

The inventory emitted by this skill uses:

- `source: aws-skill-invoked`
- `discovery_provenance.source_type: skill_invoked_pull`
- `discovery_provenance.observed_via: skill_invoked_pull, aws_sdk`
- sanitized `metadata.permissions_used`
- sanitized `cloud_origin`, `cloud_principal`, lifecycle fields, packages, and
  MCP server launch metadata

If schema validation fails, stop and fix the inventory instead of scanning a
best-effort or prose summary.

The skill does not push inventory to an API by default. Any push, scan, or
managed control-plane handoff must be a separate operator-approved handoff
command with the destination URL, auth method, and retained evidence classes
made explicit.
