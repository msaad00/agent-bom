# Gateway Auto-Discovery From the Control Plane

`agent-bom gateway serve --from-control-plane` lets the gateway load remote MCP
upstreams directly from fleet and scan data already stored in the control plane.

This avoids starting from a blank `upstreams.yaml` for every pilot.

If you are still deciding whether the right surface is `gateway`, `proxy`, or
plain `fleet` inventory, see [When To Use Proxy vs Gateway vs
Fleet](proxy-vs-gateway-vs-fleet.md).

## What auto-discovery does

The gateway pulls:

- `GET /v1/gateway/upstreams/discovered`

That endpoint aggregates tenant-scoped remote MCP servers already surfaced by:

- endpoint fleet sync
- in-cluster scans
- other scan results stored in the tenant's job history

Important boundaries:

- only remote `http` / `https` / `sse` upstreams are returned
- `stdio` MCPs are intentionally excluded
- discovered upstreams always come back with `auth: "none"`
- credentials stay in Secrets and are overlaid locally through `--upstreams`

## Minimal prerequisites

You need:

1. a control plane with discovered MCP servers for the tenant
2. a gateway bearer token or API key that can read the discovery endpoint
3. remote MCPs that actually expose HTTP/SSE transport

## Minimal worked example

Start the gateway from discovered upstreams only:

```bash
agent-bom gateway serve \
  --bind 0.0.0.0:8090 \
  --from-control-plane https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_CONTROL_PLANE_TOKEN" \
  --bearer-token "$AGENT_BOM_GATEWAY_BEARER_TOKEN"
```

Overlay secrets or transport-specific auth with a local YAML file:

```bash
agent-bom gateway serve \
  --bind 0.0.0.0:8090 \
  --from-control-plane https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_CONTROL_PLANE_TOKEN" \
  --upstreams gateway-upstreams.overlay.yaml \
  --bearer-token "$AGENT_BOM_GATEWAY_BEARER_TOKEN"
```

Example overlay:

```yaml
upstreams:
  - name: github
    url: https://mcp.github.example.com/sse
    auth: bearer
    token_env: GITHUB_MCP_TOKEN
```

## Validation flow

### 1. Validate discovery at the control plane

```bash
curl -s \
  -H "Authorization: Bearer $AGENT_BOM_CONTROL_PLANE_TOKEN" \
  https://agent-bom.internal.example.com/v1/gateway/upstreams/discovered | jq
```

Expected response shape:

```json
{
  "tenant_id": "tenant-alpha",
  "source": "fleet_scan_aggregate",
  "upstreams": [
    {
      "name": "jira",
      "url": "https://mcp.example.internal/jira",
      "transport": "sse",
      "auth": "none",
      "source_agents": ["mac-laptop-1", "windows-laptop-3"]
    }
  ],
  "conflicts": []
}
```

### 2. Validate gateway startup

At boot, the gateway prints the number and names of discovered upstreams.

Healthy startup looks like:

```text
discovered 2 upstream(s) from https://agent-bom.internal.example.com: github, jira
agent-bom gateway serving on http://0.0.0.0:8090 fronting 2 upstream(s): github, jira
```

### 3. Validate runtime posture

```bash
curl -s http://127.0.0.1:8090/healthz | jq
```

Look for:

- `status: ok`
- expected `upstreams`
- `auth.incoming_token_required`
- runtime rate-limit posture

### 4. Validate policy flow

If proxies or clients route tool traffic through the gateway, validate:

- the gateway can fetch policy from the control plane
- audit reaches `/v1/proxy/audit`
- requests to blocked tools are denied with gateway policy errors

## Discovery edge cases

### Name collisions

If two different URLs are discovered with the same MCP name:

- the first entry keeps the bare name
- later entries are renamed with suffixes such as `jira-1`
- the API returns a `conflicts` array so the operator can reconcile names

This avoids silently collapsing two different upstreams into one.

### Empty discovery

If a tenant only has `stdio` MCPs, discovery returns an empty list. That is not
an error; it just means the gateway has nothing remote to front.

## EKS shape

For a customer EKS deployment, the normal sequence is:

1. deploy the control plane
2. push endpoint fleet sync or run cluster scans
3. verify `/v1/gateway/upstreams/discovered`
4. deploy the gateway with `--from-control-plane`
5. overlay any per-upstream credentials from Secrets

That keeps the source of truth in the control plane while keeping secrets out of
scan results.

## Related guides

- [Your Own AWS / EKS](own-infra-eks.md)
- [AWS Company Rollout](aws-company-rollout.md)
- [Packaged API + UI Control Plane](control-plane-helm.md)
- [Endpoint Fleet](endpoint-fleet.md)
