# Single sign-on (OIDC) — 5-minute setup

Turn on **"Sign in with Google"** (or any OIDC issuer) for the agent-bom
dashboard without hand-wiring environment variables. The guided command
collects your IdP details, validates the issuer, and emits the exact
`AGENT_BOM_OIDC_*` configuration.

This is the onboarding path for the browser auth-code + PKCE SSO mechanism
documented in
[`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md#authentication) — it does
not change how tokens are validated. Reverse-proxy SSO
(`AGENT_BOM_TRUST_PROXY_AUTH=1`) remains the preferred posture for larger fleets;
this path is the fastest for a solo self-hoster.

---

## The command

```bash
agent-bom auth setup-oidc
```

Interactive on a terminal — it prompts for the provider, client ID/secret, and
your deployment's base URL. Fully flag-driven for automation:

```bash
agent-bom auth setup-oidc \
  --non-interactive \
  --provider google \
  --client-id  <client-id>.apps.googleusercontent.com \
  --client-secret <client-secret> \
  --base-url https://abom.example.com \
  --write                      # write deploy/secrets/oidc.env (default path)
```

It prints the provider-side steps, a copy-paste env block, and (with `--write`
or an interactive confirmation) saves the block to `deploy/secrets/oidc.env`.

> The redirect URI is always derived as `<base-url>/v1/auth/oidc/callback` — the
> dashboard's OIDC callback route. It must be allowlisted at the IdP **exactly**.

---

## Sign in with Google

1. **Google Cloud Console → APIs & Services → Credentials.**
2. **Create Credentials → OAuth client ID → Application type: Web application.**
3. Add an **Authorized redirect URI**, exactly:
   `https://<your-host>/v1/auth/oidc/callback`
4. **Create**, then copy the **Client ID** and **Client secret**.
5. Run the command with those values (issuer is preset to
   `https://accounts.google.com`):

   ```bash
   agent-bom auth setup-oidc --provider google \
     --client-id <id>.apps.googleusercontent.com \
     --client-secret <secret> \
     --base-url https://<your-host> --write
   ```

6. Load the emitted env on the API process and restart, then open the dashboard
   `/login` → **Sign in with SSO**.

Resulting env block:

```dotenv
AGENT_BOM_OIDC_ISSUER=https://accounts.google.com
AGENT_BOM_OIDC_CLIENT_ID=<id>.apps.googleusercontent.com
AGENT_BOM_OIDC_CLIENT_SECRET=<secret>
AGENT_BOM_OIDC_REDIRECT_URI=https://<your-host>/v1/auth/oidc/callback
AGENT_BOM_OIDC_AUDIENCE=<id>.apps.googleusercontent.com
AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1
```

- **`AGENT_BOM_OIDC_AUDIENCE`** defaults to the client ID — the browser ID
  token's `aud` claim is the OAuth client ID.
- **`AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT=1`** is emitted for a single-tenant
  self-host so SSO users resolve to the default tenant. Google emits no tenant
  claim, and multi-tenant enforcement is fail-closed by default. Configure a
  `--tenant-claim` instead when running multi-tenant (see below).

### Loading the env

- **Docker Compose:** the `deploy/secrets/oidc.env` file is written mode `0644`
  so the (non-root) API container can read it when mounted as an `env_file`.
  Because it may contain a client secret, restrict the `deploy/secrets/`
  directory and never commit it.
- **systemd / bare process:** export the variables into the API process
  environment (an `EnvironmentFile=` works with the same dotenv file).

---

## Generic OIDC (Okta, Entra ID, Auth0, Keycloak)

Use `--provider generic` and pass the issuer explicitly. The `.well-known/openid-configuration`
discovery document under the issuer is what the wizard validates.

| IdP        | Issuer example                                             |
|------------|-------------------------------------------------------------|
| Okta       | `https://<org>.okta.com`                                    |
| Entra ID   | `https://login.microsoftonline.com/<tenant-id>/v2.0`        |
| Auth0      | `https://<tenant>.us.auth0.com/`                            |
| Keycloak   | `https://<host>/realms/<realm>`                             |

```bash
agent-bom auth setup-oidc --provider generic \
  --issuer https://<org>.okta.com \
  --client-id <client-id> \
  --client-secret <client-secret> \
  --base-url https://<your-host> \
  --role-claim groups \
  --tenant-claim org_id \
  --write
```

- A **PKCE public client** (no secret) is supported — omit `--client-secret`.
- `--role-claim` maps a JWT claim to an agent-bom role (default `agent_bom_role`;
  `roles`/`groups`/`permissions` arrays are also honored).
- `--tenant-claim` maps a JWT claim to a tenant. When set, the wizard does **not**
  emit `AGENT_BOM_OIDC_ALLOW_DEFAULT_TENANT` — tenancy comes from the claim.

If the issuer is unreachable when you run the command (offline/air-gapped), the
wizard prints a warning and still emits a valid env block — verify the issuer URL
by hand.

---

## Reference

- Auth mechanisms and the browser SSO route: [`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md#authentication)
- Claim mapping and tenant enforcement: `src/agent_bom/api/oidc.py`
- Compose secrets layout: [`../deploy/secrets/README.md`](../deploy/secrets/README.md)
