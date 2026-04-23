# Self-Hosted Product Architecture

This is the short, truthful product contract behind the self-hosted deployment
diagrams.

`agent-bom` is not one giant process. It is a small set of roles that work
together inside the customer's environment.

## The control-plane rule

- the browser UI drives workflows
- the API owns auth, RBAC, tenant scope, orchestration, persistence, graph,
  audit, and policy state
- workers do scan and ingest jobs
- proxy and gateway handle live MCP traffic
- the Node.js UI is never the collector

That split is what keeps the deployment secure, scalable, and true to the code.

For the detailed browser-to-API trust contract, see
[UI, API, Auth, and Session Model](auth-and-session-model.md).

## What each surface actually does

| Surface | Runs where | Owns | Does not own |
|---|---|---|---|
| **UI** | browser, same-origin behind the customer's ingress | source setup, run-now actions, schedule management, review, export | direct cloud reads, repo scans, or runtime collection |
| **API / control plane** | customer VPC / EKS / self-managed compute | auth, RBAC, tenant scope, job orchestration, graph, findings, audit, policy, exports | inline MCP enforcement |
| **Workers** | CronJob, Job, CI runner, or one-off execution path | repo, image, IaC, MCP config, package, and cloud scan execution; artifact parsing; pushed-ingest normalization | browser sessions or UI state |
| **Proxy** | sidecar or local wrapper near selected MCP workloads | low-latency MCP inspection, local allow or warn decisions, audit relay | central policy storage or operator review |
| **Gateway** | customer-managed service in the runtime MCP plane | shared policy evaluation, upstream discovery, remote MCP relay, audit push to the API | full control-plane persistence or browser workflows |
| **Stores** | Postgres required; ClickHouse and S3 optional | transactional state, analytics, backups, SBOM archive | orchestration or runtime policy decisions |

## Deployment truth

In a normal self-hosted rollout:

1. operators use the UI through the customer's ingress
2. the UI talks to the API over same-origin routes
3. scheduled workers and CI jobs send results and inventory into the API
4. endpoint or collector surfaces push fleet data into the API
5. proxy and gateway send runtime audit into the API
6. the API persists state to Postgres and optionally projects analytics or
   backups elsewhere

That means the product can feel end to end without making the browser do
privileged collection work.

## Adoption truth

There are two valid starting points:

- **inventory and discovery first** through scans, imports, and fleet sync
- **runtime enforcement** through proxy or gateway where live MCP control is worth the operational overhead

That does not make runtime secondary. It makes the product easier to adopt
without pretending inventory depends on a full proxy rollout.

## Intake paths that are real today

The backend can collect or accept data through these code-backed paths:

- API-triggered scan jobs
- scheduled workers and CronJobs
- CI pushes and imports
- fleet sync into `/v1/fleet/sync`
- traces and pushed results into the API
- proxy or gateway audit into `/v1/proxy/audit`
- imported artifacts such as SBOMs or external scanner JSON

Some connector and credential-management surfaces are still maturing, but the
core intake rule is already stable: every supported path goes through the API,
workers, imports, or proxy and gateway flows.

## What the diagrams are trying to show

Use the two deployment diagrams with this reading order:

1. **deployment topology** answers "what runs in the customer's environment?"
2. **runtime MCP flow** answers "how does an MCP request move through proxy,
   gateway, API, and the upstream?"

If a diagram tries to answer both at once, it becomes harder to read and easier
to misrepresent.

## Operator checklist

If the product is wired correctly, an operator should be able to answer all of
these from the control plane:

- what source or runtime path is configured
- who owns it
- how it authenticates
- what tenant it belongs to
- when it last ran
- what evidence or audit trail it produced
- which policy applies to it

If the UI cannot answer those questions, the control plane is not fully
productized yet.

## Related docs

- [Deployment Overview](../deployment/overview.md)
- [Deploy In Your Own AWS / EKS Infrastructure](../deployment/own-infra-eks.md)
- [Packaged API + UI Control Plane](../deployment/control-plane-helm.md)
- [UI, API, Auth, and Session Model](auth-and-session-model.md)
- [Hosted Product Control-Plane Spec](hosted-product-spec.md)
