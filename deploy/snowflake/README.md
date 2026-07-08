# agent-bom on Snowflake

Deployment assets for running agent-bom **inside Snowflake**, so scan findings,
fleet state, and gateway policy live next to the rest of your Snowflake data and
never leave your account. There are two packagings here:

1. **Snowpark Container Services (SPCS)** — deploy the API + dashboard as
   long-running services with a Streamlit-in-Snowflake operator view. Set up by
   hand from `setup.sql`.
2. **Snowflake Native App** — the same platform packaged as an installable app
   (`native-app/`) with managed grants, network policies, and versioned schema
   migrations.

> For the design and data-boundary rationale, see the
> [Snowflake backend guide](../../site-docs/deployment/snowflake-backend.md) and
> the [Snowflake POV walkthrough](../../site-docs/deployment/snowflake-pov.md).

## Files

| File | Purpose |
| --- | --- |
| `setup.sql` | One-shot SPCS bring-up: database/schema, the four backing tables (`scan_jobs`, `fleet_agents`, `gateway_policies`, `policy_audit_log` — the same schema `snowflake_store.py` auto-creates), image repository, compute pool, and the `agent_bom_service`. |
| `service-spec.yaml` | SPCS service spec for the two containers — the FastAPI API (`8422`) and the Next.js UI (`3000`). Both share the service network namespace, so the UI reaches the API on `localhost` with **no public egress**; both endpoints are declared `public: false`. |
| `streamlit_app.py` | Streamlit-in-Snowflake dashboard that reads the backing tables **directly** (no HTTP round-trip) via `st.connection("snowflake")`. |
| `environment.yml` | Conda environment (`plotly`, `pandas`) for the Streamlit-in-Snowflake app. |
| `native-app/` | Snowflake Native App packaging — see below. |

### `native-app/`

| Path | Purpose |
| --- | --- |
| `manifest.yml` | Native App manifest: version, the four container images, default web endpoint, and the `api` / `ui` / `scanner` / `mcp_runtime` service roles with per-endpoint USAGE grants. |
| `scripts/setup.sql` | App setup script run on install/upgrade. |
| `scripts/customer_grants_template.sql` | Template for the account-level grants the consumer must approve. |
| `scripts/auth_keypair_setup.sql` | Key-pair auth setup — short-lived key-pair auth, **no passwords**. |
| `scripts/network_policies.sql` | Egress network policies for the app's services. |
| `dcm/V001__core_schema.sql`, `dcm/V002__compliance_proc.sql` | Versioned (Declarative Change Management) schema migrations. |
| `service-specs/scanner-service.yaml`, `service-specs/mcp-runtime-service.yaml` | Opt-in scanner and MCP-runtime service specs, enabled only after the consumer calls the matching `enable_*` procedure. |
| `streamlit/dashboard.py` | Native App Streamlit dashboard. |

## Quickstart (SPCS)

Run the contents of `setup.sql` in a Snowflake worksheet (or `!source` it from
`snowsql`), then push the image and start the service:

```bash
# Push the image to the repository created by setup.sql
docker tag agent-bom:latest \
  <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
docker push \
  <account>.registry.snowflakecomputing.com/agent_bom/public/agent_bom_repo/agent-bom:latest
```

```sql
-- Check status once the image is pushed
CALL SYSTEM$GET_SERVICE_STATUS('agent_bom_service');
CALL SYSTEM$GET_SERVICE_LOGS('agent_bom_service', '0', 'agent-bom', 100);
```

For the packaged experience, build and install the app from `native-app/`
instead of running `setup.sql` by hand.

## Data & security posture

- **Findings stay in your account.** The API writes to Snowflake tables in your
  database; the Streamlit dashboard reads them directly. Nothing is shipped to
  an external control plane.
- **No public egress by default.** Both SPCS endpoints are `public: false`;
  access is via the Snowflake ingress URL / service roles, not an open port.
- **Least-privilege service roles.** The Native App exposes separate `api`,
  `ui`, `scanner`, and `mcp_runtime` roles, each granting USAGE on only its own
  endpoint. Scanner and MCP-runtime services are opt-in.
- **No passwords.** Programmatic auth uses short-lived key-pair auth
  (`native-app/scripts/auth_keypair_setup.sql`); Snowflake account/database/
  schema are passed as environment references, never secrets baked into these
  files.

## Related docs

- [Snowflake backend guide](../../site-docs/deployment/snowflake-backend.md)
- [Snowflake POV walkthrough](../../site-docs/deployment/snowflake-pov.md)
