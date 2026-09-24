# Remote MCP with an external OAuth issuer

The remote MCP server can use an operator-owned OAuth authorization server.
This is an opt-in alternative to static MCP bearer credentials. API/UI OIDC,
SAML, API keys, gateway authentication, and stdio keep their existing behavior.
The issuer handles login, consent, client registration and token renewal;
Agent-Bom validates access tokens and never issues them.

## Start the resource server

Install `agent-bom[oidc,mcp-server]` and configure:

```bash
export AGENT_BOM_MCP_PUBLIC_URL=https://mcp.example.com
export AGENT_BOM_MCP_OAUTH_ISSUER=https://identity.example.com/realms/agent-bom
export AGENT_BOM_MCP_OAUTH_AUDIENCE=https://mcp.example.com/mcp
export AGENT_BOM_MCP_OAUTH_JWKS_URI=https://identity.example.com/realms/agent-bom/protocol/openid-connect/certs
export AGENT_BOM_MCP_OAUTH_SUBJECTS=approved-user-subject,approved-probe-subject
agent-bom mcp server --transport streamable-http --host 0.0.0.0
```

Unset static MCP read/operator credentials before enabling OAuth. Partial or
conflicting configuration fails startup. The audience must exactly match the
public `/mcp` URL. Issuer and JWKS URLs must use the same HTTPS origin.

The resulting `/.well-known/oauth-protected-resource/mcp` document identifies
the resource and issuer. Anonymous requests receive 401. A valid access token
requires a verified RS256/ES256 signature, exact issuer/audience, explicit
approved subject, `read` scope, and an `iat`/`exp` interval of at most one hour.
Tokens do not grant write privileges even if they contain administrative
claims. Approved subjects share the process-bound MCP tenant; this mode does
not route subjects into different tenants. Use separate tenant deployments
where needed.

Next, connect an authorized MCP client and verify `initialize` and `tools/list`
on the supported 2025 protocol. Verify rejection without a token, with an
expired token and with a token for another audience. Confirm a newly issued
credential succeeds without restarting the MCP service.

Public keys are cached for five minutes; unknown signing keys trigger a refresh
at most once per ten seconds. A just-rotated key may require a retry. Invalid
credentials and unavailable keys fail closed. Removal from the configured
subject allowlist requires a process restart; issued access tokens otherwise
remain valid until expiry. Roll back by restoring the prior deployment and
its valid authentication configuration, never by disabling authentication.

## Self-hosted Keycloak setup

Use a supported, security-patched Keycloak release and persistent PostgreSQL.
Deploy it as a separate service with its own credentials, public HTTPS hostname,
restricted administrator access, backups, and readiness checks. Do not use
`start-dev` or an ephemeral database for a hosted service.

In a dedicated realm:

1. Disable public user registration; provision approved users and require MFA
   where appropriate. Set access-token lifetime to five minutes.
2. Create a `read` client scope with an audience mapper targeting the exact MCP
   endpoint URL. Include the scope in the access token.
3. Register approved interactive clients with exact redirect URIs,
   authorization-code flow, PKCE S256 and user consent. Do not enable password
   grants or broad redirect wildcards.
4. Create a separate confidential service-account client for CI. Grant only
   the `read` scope and MCP audience. Record its subject in the MCP allowlist;
   do not grant Keycloak administration roles.
5. Verify the actual client's registration mechanism. Keycloak documents
   resource-indicator limitations and a scope/audience mapper workaround.
   Its Client ID Metadata Document support is experimental. Neither a
   successful token request nor enabling dynamic registration proves Smithery
   interoperability; test discovery, login/consent and tool listing end to end.

See [Keycloak's MCP integration guide](https://www.keycloak.org/securing-apps/mcp-authz-server).
The current MCP specification prefers Client ID Metadata Documents; dynamic
registration is retained for backward compatibility. Configure only the
mechanism required by tested clients and preserve explicit authorization.

## Familiar sign-in for people

Keycloak can broker Google, GitHub, Microsoft Entra ID, or an organization's
SAML/OIDC provider. Configure the provider's application registration and exact
Keycloak callback URI, then enable only the providers used by the deployment.
For a developer-facing installation, Google and GitHub are useful entry points;
enterprise installations can present a single company SSO option. Avoid a long
list of unused login buttons.

The interactive flow is MCP client → Keycloak → chosen identity provider →
Keycloak consent → MCP client. Use authorization code with PKCE S256. Keycloak
issues the access token for the MCP audience; Google/GitHub login tokens are not
accepted as MCP access tokens. Successful social login alone must not grant MCP
access: approve the resulting Keycloak subject explicitly. Do not automatically
link accounts based only on an unverified email address.

Provider credentials belong in Keycloak's protected configuration, never the MCP
client, repository, or browser bundle. CI uses its separate service account and
does not open a browser. Existing API/UI SSO remains independently configured.
See the [Keycloak identity brokering guide](https://www.keycloak.org/docs/latest/server_admin/#_identity_broker).

### Railway issuer deployment

The [Keycloak deployment example](../deploy/keycloak/README.md) builds an
optimized, pinned image backed by PostgreSQL. Deploy the issuer separately,
verify realm discovery, and then configure the resource server above. Deploying
an issuer does not enable a social provider or authorize an MCP client by itself.

## Fresh credentials for CI probes

Configure repository variables:

- `MCP_PROBE_OAUTH_ISSUER`
- `MCP_PROBE_OAUTH_TOKEN_URL` (same HTTPS origin as the issuer)
- `MCP_PROBE_OAUTH_AUDIENCE` (the exact MCP endpoint)
- `MCP_PROBE_OAUTH_CLIENT_ID`

Store `MCP_PROBE_OAUTH_CLIENT_SECRET` as a GitHub Actions secret. This confidential
client credential still needs operator-managed rotation; the access tokens are
issued automatically for each run. Client-credentials authentication avoids
browser SSO in CI. Workload federation is a separate provider-specific setup.

```bash
PYTHONPATH=src python scripts/deploy/probe_with_oauth.py -- \
  --base-url https://mcp.example.com/mcp --server-card --require-mcp-auth \
  --expected-version RELEASE_VERSION --expected-tool-count RELEASE_TOOL_COUNT
```

The helper requests a bounded read token, then passes it through the probe's
process environment rather than its command line or logs. It rejects redirects,
incomplete configuration and excessive token lifetimes. With no OAuth settings,
it preserves the existing `RAILWAY_MCP_BEARER_TOKEN` path.

Next, run Deployment Freshness and compare exact tool schemas against the
published release. Public health or server-card responses alone do not establish
that protected MCP requests work.
