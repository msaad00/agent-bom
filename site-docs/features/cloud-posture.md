# Cloud Posture and IaC Gates

agent-bom treats cloud posture as two connected checks over the same evidence
model:

1. **Pre-cloud IaC gates** catch misconfigurations before Terraform,
   CloudFormation, Kubernetes, or Docker changes reach an account or cluster.
2. **Runtime cloud posture checks** verify the deployed account or service
   state after drift, console changes, inherited policies, and provider-side
   defaults exist.

Use both lanes when possible. The IaC lane is the default pull-request and
release gate because it is fast, read-only, and blocks unsafe changes before
deployment. The runtime lane is the drift and assurance check because it sees
what actually exists in the cloud.

## Pre-cloud lane

Run the focused IaC scanner before apply:

```bash
agent-bom iac Dockerfile k8s/ infra/main.tf --format sarif --output agent-bom-iac.sarif
```

In GitHub Actions, use the `iac` scan type or the `iac` input:

```yaml
- uses: msaad00/agent-bom@v0.94.2
  with:
    scan-type: iac
    scan-ref: infra/main.tf,k8s/
    format: sarif
    upload-sarif: true
    severity-threshold: high
```

The IaC scanner is read-only. It analyzes local files and emits findings,
policy context, SARIF, JSON, or other report formats without applying
infrastructure.

Supported pre-cloud inputs include:

- Terraform
- CloudFormation
- Kubernetes manifests and Helm-rendered output
- Dockerfiles

## Runtime posture lane

Run cloud benchmark checks against the actual environment when credentials are
available:

```bash
agent-bom cloud aws --cis
agent-bom cis-benchmark --provider azure
agent-bom cis-benchmark --provider gcp
agent-bom cis-benchmark --provider snowflake
```

These checks are for deployed state, not planned state. They catch drift and
environment properties that do not appear in a pull request, such as:

- manually changed identity or logging settings
- inherited organization, subscription, or project policy
- cloud-provider defaults
- resources created outside the reviewed IaC path
- service posture that depends on account-level configuration

Connected accounts can also be scanned on a recurring schedule from the control
plane. That makes posture near-continuous at the chosen cadence: new resources
or deployments are discovered on the next run, removed resources appear in graph
history/diff as deleted evidence, and findings are regenerated from the latest
read-only inventory.

The default mode is scheduled polling. When an operator wires the optional event
queues, agent-bom can also consume AWS CloudTrail/EventBridge events from SQS,
Azure Activity Log/Event Grid events from Storage Queue, and GCP Cloud Asset or
Audit Log events from Pub/Sub. Those consumers are bounded, provider-scoped, and
re-evaluate the affected resource class through the same read-only connection.
If no event queue is configured, the connection falls back to scheduled or
manual scans.

## How to read the result

The useful question is not "IaC or CSPM?" It is:

| Moment | Best command | What it proves |
|---|---|---|
| Before merge | `agent-bom iac ...` | Proposed infrastructure does not introduce known high-risk misconfiguration |
| Before apply | `agent-bom iac ... --format sarif` in CI | The exact deployment artifact passed the gate |
| After deploy | `agent-bom cis-benchmark --provider ...` | The live environment still satisfies benchmark expectations |
| During investigation | graph exposure paths and findings APIs | Misconfiguration, packages, agents, credentials, and runtime evidence can be reviewed together |

## Boundary

agent-bom does not apply Terraform, mutate CloudFormation stacks, or change
cloud settings as part of posture scanning. It reports evidence and exits with
deterministic codes so the operator, CI system, or control plane can decide
whether to block, approve, or open a remediation workflow.

The current CSPM/CIS lane should be positioned as read-only inventory,
benchmark checks, IaC misconfiguration detection, scheduled drift visibility,
and graph-backed attack paths. Full DSPM requires classifier-backed content
inspection and data-access resolution; Snowflake has the deepest metadata,
grant, tag, and lineage coverage today, while other stores remain
metadata/posture based unless imported classifier evidence is present.
