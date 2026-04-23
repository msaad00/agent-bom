# Helm Example Profiles

These files are the canonical packaged deployment profiles for the `agent-bom`
Helm chart. They are meant to reduce day-0 decision sprawl, not create a new
product split.

## Shipped profiles

| Profile | File | Intended use |
|---|---|---|
| `sqlite-pilot` | `eks-control-plane-sqlite-pilot-values.yaml` | Single-node packaged demo or short-lived pilot where Postgres is not ready yet |
| `focused-pilot` | `eks-mcp-pilot-values.yaml` | Narrow EKS pilot with control plane, scanner, and tightened ingress |
| `production` | `eks-production-values.yaml` | Postgres-backed production EKS rollout with autoscaling, backup, and ExternalSecrets |
| `mesh-hardening` | `eks-istio-kyverno-values.yaml` | Overlay for Istio mTLS/authz and Kyverno policy-controller packaging |
| `snowflake-backend` | `eks-snowflake-values.yaml` | Overlay for Snowflake governance and selected store parity, not a claim of full control-plane replacement |
| `gateway-runtime` | `eks-mcp-pilot-values.yaml` + `gateway-upstreams.example.yaml` | Focused pilot plus central gateway rendering for shared MCP relay/policy |

## Validate the shipped profiles

With Helm installed:

```bash
python scripts/validate_helm_profiles.py
```

List the profile names without rendering:

```bash
python scripts/validate_helm_profiles.py --list
```

Render only one profile:

```bash
python scripts/validate_helm_profiles.py --profile focused-pilot
```

## Install a shipped profile in one command

Print the exact Helm command for a profile:

```bash
python scripts/install_helm_profile.py focused-pilot --print-command
```

Run the packaged focused EKS pilot profile directly:

```bash
python scripts/install_helm_profile.py focused-pilot
```

Append your own values file or targeted overrides without forking the shipped profile:

```bash
python scripts/install_helm_profile.py production \
  --values ./my-prod-overrides.yaml \
  --set controlPlane.ingress.hosts[0].host=agent-bom.acme.internal
```

## Operator guidance

- Start with `focused-pilot` for the narrow customer EKS story.
- Use `sqlite-pilot` only for demos or single-node packaged pilots.
- Move to `production` once Postgres, ingress, and backup ownership are real.
- Treat `mesh-hardening` and `snowflake-backend` as overlays, not separate products.
- Treat `snowflake-backend` as a warehouse-native deployment mode with explicit parity boundaries, not the default production path.
- Gateway remains an optional runtime surface layered onto the control plane, not a mandatory chokepoint.
