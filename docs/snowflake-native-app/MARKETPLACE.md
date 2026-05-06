# Snowflake Marketplace release lane

This is the provider-side checklist for publishing agent-bom as a Snowflake
Native App. It is intentionally dry-run first: the GitHub Actions lane packages
the app and validates the manifest, but live publish remains blocked until the
Marketplace listing has been reviewed and explicit Snowflake publisher secrets
are configured.

## Listing draft

| Field | Draft value |
|---|---|
| Listing name | agent-bom - AI Supply Chain Security |
| Category | Security and Governance |
| Delivery method | Snowflake Native App with Snowpark Container Services |
| Data boundary | Customer account only; no customer data leaves Snowflake |
| Default egress | Off |
| Optional egress | OSV.dev, CISA KEV, FIRST EPSS, GitHub Advisory Database |
| Runtime services | API/UI by default; scanner and MCP runtime are opt-in |

## Required proof before publish

- Manifest review proves references are customer-bound and read-only.
- Service specs validate as YAML and declare internal-only endpoints.
- Advisory egress is attached only to `core.enable_scanner_service()`.
- MCP runtime is not created during install and requires a caller-supplied
  bearer token.
- The release workflow is manually dispatched and defaults to `dry_run: true`.
- If no version input is supplied, the workflow derives the Snowflake package
  label from `pyproject.toml` (`0.86.0` -> `v0_86_0`) so package labels do not
  drift from the release version.
- Live publish requires the protected `snowflake-marketplace` environment plus
  `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY`, and
  `SNOWFLAKE_APPLICATION_PACKAGE`.

## Manual dry run

```bash
python - <<'PY'
from pathlib import Path
import yaml

root = Path("deploy/snowflake/native-app")
yaml.safe_load((root / "manifest.yml").read_text())
for spec in sorted((root / "service-specs").glob("*.yaml")):
    data = yaml.safe_load(spec.read_text())
    assert data.get("spec", {}).get("containers"), spec
PY

mkdir -p dist
tar -czf dist/agent-bom-snowflake-v0_86_0.tgz -C deploy/snowflake/native-app .
```

## Customer smoke checklist

Run this checklist in a private-preview account before requesting Marketplace
review:

```sql
CALL agent_bom.core.health_check();
SHOW SERVICES IN APPLICATION agent_bom;
SHOW EXTERNAL ACCESS INTEGRATIONS LIKE 'AGENT_BOM_%';
```

Expected state after install:

- `core.agent_bom_api` exists and exposes the UI endpoint.
- `core.agent_bom_scanner` does not run until
  `core.enable_scanner_service()` is called.
- `core.agent_bom_mcp_runtime` does not run until
  `core.enable_mcp_runtime_service('<token>')` is called.
- Advisory-feed EAIs remain disabled/unbound until the customer explicitly
  approves OSV, CISA KEV, FIRST EPSS, and GHSA.

## Live publish status

Not enabled in this PR. The workflow stops before calling Snowflake when
`dry_run` is false, so no Marketplace channel can be mutated by accident.
