#!/usr/bin/env bash
# agent-bom Databricks read-only provisioning
#
# Databricks has two auth paths depending on your deployment:
#   A. PAT (Personal Access Token) — simplest, scoped to user permissions
#   B. OAuth M2M (Machine-to-Machine) — recommended for CI/CD, no user identity
#
# Databricks uses its own permission model (not IAM). Permissions are set at:
#   - Workspace level (cluster access, endpoint access)
#   - Unity Catalog level (metadata read on catalogs/schemas)
#   - Platform level (model serving, jobs)
#
# Docs:
#   PAT:      https://docs.databricks.com/en/dev-tools/auth/pat.html
#   OAuth M2M: https://docs.databricks.com/en/dev-tools/auth/oauth-m2m.html
#   Unity Catalog permissions: https://docs.databricks.com/en/data-governance/unity-catalog/manage-privileges/privileges.html
#   SDK credential chain: https://docs.databricks.com/en/dev-tools/sdk-python.html#authentication

set -euo pipefail

DATABRICKS_HOST="${DATABRICKS_HOST:-}"
if [[ -z "$DATABRICKS_HOST" ]]; then
  echo "ERROR: Set DATABRICKS_HOST (e.g. https://adb-<id>.azuredatabricks.net)"
  exit 1
fi

# ─── Option A: PAT (quick setup) ────────────────────────────────────────────
# Create in Databricks UI: User Settings → Developer → Access Tokens → Generate
# Scope: the token inherits your user's permissions.
# Minimum permissions your user needs:
#   - CAN VIEW on clusters (Settings → Compute)
#   - CAN VIEW on model serving endpoints (Settings → Serving)
#   - CAN VIEW on jobs (if scanning ML training jobs)
#   - SELECT privilege on Unity Catalog (for package/model metadata)
# Token lifetime: set the shortest expiry your workflow allows (max 730 days).
# Rotate: generate a new token, update the env var, revoke the old one.

# ─── Option B: OAuth M2M (recommended for CI/CD) ─────────────────────────────
# 1. Create a Service Principal in Databricks account console
#    https://accounts.azuredatabricks.net → User Management → Service Principals
databricks_sp_name="agent-bom-scanner"
echo "Creating service principal: $databricks_sp_name"
echo "(Run in Databricks CLI or via account console UI)"
# databricks service-principals create --display-name "$databricks_sp_name"

# 2. Generate an OAuth secret for the service principal
# databricks service-principals get-secret --sp-id <SP_ID>

# 3. Grant workspace-level permissions to the service principal
#    In workspace: Admin Settings → Identity and Access → Service Principals
#    Minimum grants:
#      - Workspace access: YES
#      - Cluster access: CAN VIEW (not CAN MANAGE)
#      - Model Serving: CAN VIEW
#      - Jobs: CAN VIEW (for ML training job scanning)

# 4. Grant Unity Catalog permissions (metadata only — no data read)
#    In Databricks SQL or notebook:
cat << 'SQL'
-- Grant read-only metadata access to agent-bom service principal
-- Replace <SP_NAME> with your service principal display name

GRANT USE CATALOG ON CATALOG main TO `<SP_NAME>`;
GRANT USE SCHEMA ON SCHEMA main.default TO `<SP_NAME>`;
-- SELECT is only needed if scanning model metadata stored in Delta tables
-- DO NOT grant MODIFY, CREATE, or ALL PRIVILEGES

-- For model registry (MLflow models in Unity Catalog):
GRANT USE CATALOG ON CATALOG main TO `<SP_NAME>`;
SQL

echo ""
echo "Usage — PAT:"
echo "  export DATABRICKS_HOST=https://adb-<id>.azuredatabricks.net"
echo "  export DATABRICKS_TOKEN=<pat-token>"
echo "  agent-bom scan --databricks"
echo ""
echo "Usage — OAuth M2M:"
echo "  export DATABRICKS_HOST=https://adb-<id>.azuredatabricks.net"
echo "  export DATABRICKS_CLIENT_ID=<sp-client-id>"
echo "  export DATABRICKS_CLIENT_SECRET=<sp-oauth-secret>"
echo "  agent-bom scan --databricks"
echo ""
echo "Usage — ~/.databrickscfg profile (no env vars needed):"
echo "  databricks configure --profile agent-bom"
echo "  agent-bom scan --databricks"
