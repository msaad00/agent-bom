# OIDC discovery shim for MCP clients

Many MCP OAuth clients auto-discover IdP endpoints via
`/.well-known/openid-configuration` at the configured issuer URL. Enterprise
buyers often run IdPs that issue valid tokens but **do not publish** discovery
metadata in the shape MCP tooling expects — or they publish it on a different
host than the issuer the MCP client is configured to use.

agent-bom already ships:

- **Control-plane OIDC login** — JWT verification for the API and dashboard
  (`AGENT_BOM_OIDC_ISSUER`, tenant-bound providers).
- **Gateway authentication** — configured bearer/API-key credentials and
  external OIDC/JWKS identity verification. Embedded OAuth token issuance is
  unavailable until trusted client authorization is implemented.

The **OIDC discovery shim** is a narrowly scoped interop path: a
read-only metadata surface that tells MCP clients where the **buyer's existing
IdP** lives. It does not mint tokens, register clients dynamically against
legacy IdPs, or grant access to gateway tools.

## When to use it

| Scenario | Use shim? | Prefer instead |
|---|---|---|
| MCP client needs `/.well-known/openid-configuration` at your gateway hostname | Yes | — |
| IdP publishes discovery but on a different issuer host | Yes (shim issuer = gateway) | Re-point MCP client if possible |
| You need MCP access tokens | No | Provision credentials through your trusted identity system |
| Browser dashboard login via reverse-proxy OIDC | No | `AGENT_BOM_OIDC_ISSUER` + `/login` |

## Architecture

```text
 MCP client (Cursor, Claude Desktop, …)
        │
        │ 1) GET /.well-known/openid-configuration
        ▼
 agent-bom gateway (discovery shim)
        │  serves static JSON from AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON
        │
        │ 2) authorization_code + PKCE (client talks to IdP directly)
        ▼
 Buyer IdP (Okta, Entra, Auth0, …)
        │ 3) access_token (RS256 JWT)
        ▼
 MCP client ──► agent-bom gateway relay ──► upstream MCP servers
```

The shim only answers step 1. Steps 2–3 stay on the buyer IdP. Register the
MCP client manually in the IdP admin console (redirect URIs, scopes, PKCE).

## Deployment

### Gateway sub-route (recommended)

Set `AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON` on the gateway deployment:

```bash
export AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON='{
  "issuer": "https://mcp-auth.acme.internal",
  "authorization_endpoint": "https://acme.okta.com/oauth2/v1/authorize",
  "token_endpoint": "https://acme.okta.com/oauth2/v1/token",
  "jwks_uri": "https://acme.okta.com/oauth2/v1/keys",
  "userinfo_endpoint": "https://acme.okta.com/oauth2/v1/userinfo",
  "scopes_supported": ["openid", "profile", "email"]
}'
```

Point MCP clients at `issuer` (`https://mcp-auth.acme.internal`). Terminate TLS
at ingress so the gateway serves discovery on that hostname.

Verify:

```bash
curl -fsS "https://mcp-auth.acme.internal/.well-known/openid-configuration" | jq .
```

`GET /healthz` on the gateway reports `oidc_discovery_shim_enabled: true`.

### Helm overlay

Use the packaged example:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  -f deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml \
  -f deploy/helm/agent-bom/examples/gateway-upstreams.example.yaml \
  -f deploy/helm/agent-bom/examples/oidc-discovery-shim-values.yaml
```

Edit the JSON in `oidc-discovery-shim-values.yaml` with your IdP endpoints
before applying.

### Static nginx sidecar (ingress-only)

When you only need discovery at the edge and the gateway runs elsewhere, serve
the same JSON from a ConfigMap-backed nginx sidecar. See the commented nginx
block in `deploy/helm/agent-bom/examples/oidc-discovery-shim-values.yaml`.

## Contract

The shim document must include at minimum:

- `issuer`, `authorization_endpoint`, `token_endpoint`, `jwks_uri`
- `response_types_supported` (default `["code"]`)
- `subject_types_supported` (default `["public"]`)
- `id_token_signing_alg_values_supported` (default `["RS256"]`)

`validate_oidc_discovery_document()` in
`src/agent_bom/api/oidc_discovery_shim.py` enforces this shape. Tests live in
`tests/test_oidc_discovery_shim.py`.

## Security posture

- **Read-only metadata** — no secrets, no token minting, no outbound IdP calls.
- **Fail closed on bad config** — invalid JSON or missing required keys prevent
  gateway startup when the env var is set.
- **Not a broker** — embedded gateway token issuance is unavailable. The shim
  only publishes metadata for an independently configured trusted IdP.

## Related

- Parent epic: [#3175](https://github.com/msaad00/agent-bom/issues/3175)
- Tail issue: [#3609](https://github.com/msaad00/agent-bom/issues/3609)
- Enterprise deployment: [`ENTERPRISE_DEPLOYMENT.md`](../ENTERPRISE_DEPLOYMENT.md#mcp-oidc-discovery-shim)
- Gateway OAuth AS: `src/agent_bom/api/oauth_as.py`
