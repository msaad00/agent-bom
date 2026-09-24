# Keycloak issuer on Railway

Deploy this directory as a separate Railway service. It contains no credentials
or realm exports. The image uses production mode and requires persistent PostgreSQL.

```bash
railway up deploy/keycloak --path-as-root --service Keycloak
```

Configure these service variables before deployment:

| Variable | Value |
| --- | --- |
| `KC_DB_URL` | `jdbc:postgresql://${{Postgres.PGHOST}}:${{Postgres.PGPORT}}/${{Postgres.PGDATABASE}}` |
| `KC_DB_USERNAME` | `${{Postgres.PGUSER}}` |
| `KC_DB_PASSWORD` | `${{Postgres.PGPASSWORD}}` |
| `KC_HOSTNAME` | The issuer's public HTTPS origin |
| `KC_HOSTNAME_STRICT` | `true` |
| `KC_HTTP_ENABLED` | `true` for Railway's TLS-terminating proxy |
| `KC_HTTP_PORT` / `PORT` | `8080` |
| `KC_PROXY_HEADERS` | `xforwarded` behind the trusted Railway proxy |
| `KC_CACHE` | `local` for this single-replica example |
| `KC_BOOTSTRAP_ADMIN_USERNAME` | A temporary bootstrap administrator |
| `KC_BOOTSTRAP_ADMIN_PASSWORD` | A securely generated secret |

Use Railway's secret input facilities; do not paste passwords into shell command
arguments. Keep database traffic on Railway's private network. Configure volume
backups and verify restoration before relying on this service for production.
The example is single-replica, not a high-availability configuration.

Configure the Keycloak service's **Settings** explicitly before deploying:

| Setting | Value |
| --- | --- |
| Builder / Dockerfile path | Dockerfile / `Dockerfile` |
| Healthcheck Path | `/realms/master/.well-known/openid-configuration` |
| Healthcheck Timeout | `300` seconds |
| Restart Policy / Max restart retries | On Failure / `3` |
| Replicas | `1` |
| Serverless | Disabled |

Review the staged changes to confirm they affect only the issuer service, then
apply them. Verify the deployment passes its health check and the settings are
still present after reloading the dashboard. New services cannot opt into
Railway's deprecated [Config as Code](https://docs.railway.com/config-as-code),
so this example does not rely on a `railway.json` file.

The health check requests the master realm discovery document. After startup,
create a dedicated realm and clients following [MCP OAuth setup](../../docs/MCP_OAUTH.md).
Verify that realm's issuer, signing keys, token lifetime, audience and authorized
subjects. Require MFA for permanent administrators, verify their access, and
then remove the bootstrap administrator and its environment credentials.

The issuer and resource server are separate deployments. An issuer outage
prevents new logins and token renewal; the resource server rejects invalid
credentials or unavailable signing keys. Already issued tokens can remain valid
until expiry while their signing key is cached. Preserve the database and realm
configuration during rollback; check Keycloak database migration compatibility
before downgrading an image.
