# Focused EKS MCP Pilot

This is the recommended pilot scope for a company that wants to run
`agent-bom` in its own AWS / EKS environment specifically for:

- MCP and agent discovery
- fleet and mesh visibility
- gateway policy management
- selected inline proxy enforcement

This is intentionally narrower than a full platform rollout.

If you also want employee laptops and workstations in the same pilot, pair this
with [Endpoint Fleet](endpoint-fleet.md). That is a separate endpoint scan +
push path, not the sidecar/runtime path described here.

## Pilot scope

Enable:

- Helm-packaged API + UI control plane
- Postgres-backed persistence
- same-origin ingress
- scanner CronJob focused on MCP and agent discovery
- selected workload proxy sidecars

Leave out unless you need them:

- ClickHouse
- Snowflake backend path
- broad cloud CSPM rollout
- full runtime monitor DaemonSet on every node
- every export and output surface

## What to install

Use the packaged control-plane chart with the focused pilot values file:

- [deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml](/Users/mohamedsaad/Desktop/Agent-Bom/deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml)

Install:

```bash
helm install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml
```

That pilot profile gives you:

- packaged API + UI control plane
- same-origin ingress
- ingress restricted to the pilot namespace and the ingress controller namespace
- scanner CronJob running cluster-wide discovery
- enterprise-oriented MCP scan args:
  - `--k8s-mcp`
  - `--k8s-all-namespaces`
  - `--introspect`
  - `--enforce`
- monitor DaemonSet left disabled

## Selected inline enforcement

The honest runtime-enforcement path for this pilot is sidecar deployment on the
specific MCP workloads you want to guard.

Use:

- [deploy/k8s/proxy-sidecar-pilot.yaml](/Users/mohamedsaad/Desktop/Agent-Bom/deploy/k8s/proxy-sidecar-pilot.yaml)

This manifest shows:

- a namespace labeled for Pod Security Admission `restricted`
- a starter proxy policy `ConfigMap`
- a metrics `Service`
- a sample MCP workload with `agent-bom-runtime` sidecar
- control-plane policy pull and proxy audit push
- audit logging, undeclared tool blocking, credential detection, and basic rate limiting

Important boundary:

- `agent-bom proxy` is not a generic shared network gateway service today
- it is a stdio wrapper or local proxy-to-remote-server path
- for EKS, that means selected-workload sidecars are the honest enforcement
  model today

## What the pilot surfaces

This pilot should focus operators on a short list of product surfaces:

- `/fleet`
- `/agents`
- `/mesh`
- `/security-graph`
- `/gateway`
- `/findings`

That gives the team a clean story:

1. discover agents and MCP servers
2. inventory and score them
3. review fleet and graph posture
4. define gateway policies
5. enforce selected runtime traffic through sidecars

## Required platform hardening

Before calling this pilot production-like, apply the namespace labels and run
the control-plane migrations explicitly:

```bash
kubectl label namespace agent-bom \
  pod-security.kubernetes.io/enforce=restricted \
  pod-security.kubernetes.io/audit=restricted \
  pod-security.kubernetes.io/warn=restricted \
  --overwrite

alembic -c deploy/supabase/postgres/alembic.ini upgrade head
```

If the database was already bootstrapped from
[deploy/supabase/postgres/init.sql](/Users/mohamedsaad/Desktop/Agent-Bom/deploy/supabase/postgres/init.sql),
stamp the baseline once before future upgrades:

```bash
alembic -c deploy/supabase/postgres/alembic.ini stamp 20260416_01
```

The focused pilot values also set `networkPolicy.restrictIngress=true` and only
allow ingress from:

- the `agent-bom` namespace
- the `ingress-nginx` namespace

If your ingress controller runs elsewhere, change
[deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml](/Users/mohamedsaad/Desktop/Agent-Bom/deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml)
before install.

## Recommended secrets and auth

At minimum, put these in a Kubernetes Secret referenced by the API Deployment:

- `AGENT_BOM_POSTGRES_URL`
- `AGENT_BOM_API_KEY` or OIDC settings
- `AGENT_BOM_AUDIT_HMAC_KEY` (required for pilot sign-off; do not rely on the ephemeral fallback)

For enterprise pilots, prefer:

- OIDC for user access
- explicit `AGENT_BOM_OIDC_AUDIENCE`
- optional `AGENT_BOM_OIDC_REQUIRED_NONCE` when your IdP flow includes a nonce claim
- persistent audit HMAC keys with `AGENT_BOM_REQUIRE_AUDIT_HMAC=1`
- IRSA on the scanner service account
- internal ingress / VPN-only access

## What this pilot is not

This pilot is not trying to prove every `agent-bom` surface at once.

It is not:

- a Snowflake-native backend evaluation
- a full cloud posture rollout
- a ClickHouse analytics rollout
- a node-wide runtime monitor deployment
- a benchmarked production-scale signoff

Those can come later if the MCP + agents + fleet + proxy story lands.
