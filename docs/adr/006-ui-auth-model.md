# ADR-006: UI Authentication Model

## Status

Accepted

## Context

The packaged dashboard shipped without a defined browser authentication model. The UI assumed same-origin API access, but it did not propagate bearer credentials, did not gate protected routes, and did not document how enterprise reverse-proxy auth should work.

## Decision

The control-plane UI uses two supported browser auth modes:

1. Recommended for enterprise: same-origin reverse-proxy OIDC or SSO session. The reverse proxy terminates browser auth, keeps the session cookie, and injects trusted `X-Agent-Bom-Role` and `X-Agent-Bom-Tenant-ID` headers to the backend. `AGENT_BOM_TRUST_PROXY_AUTH=1` must be enabled on the API for this mode.
2. Fallback for local and single-user pilots: a short-lived API key entered into the dashboard. The UI exchanges it for a same-origin `httpOnly` browser session cookie and never stores or forwards the raw key from browser storage.

The UI always sends `credentials: "include"` over same-origin fetch/EventSource URLs so same-origin proxy sessions work without custom browser configuration and browser credentials cannot be redirected through runtime config. A global auth gate now blocks dashboard routes until one of the supported auth modes succeeds.

## Consequences

### Positive

- The browser auth story is explicit and consistent across backend, runtime config, and UI behavior.
- Enterprise ingress can use OIDC without exposing raw API keys to end users.
- Single-user pilots still have an explicit API-key exchange without a browser-readable bearer-token cache.

### Negative

- Multi-user browser access still depends on an external reverse proxy or the API browser-session cookie flow.
- Proxy-auth mode trusts headers and must only be enabled behind a hardened ingress that strips spoofed client headers.

### Neutral

- The dashboard no longer treats unauthenticated production deployments as undefined behavior; it shows an auth gate instead.
