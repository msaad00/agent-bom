# connect-snowflake

Mints the **read-only** grant agent-bom's Snowflake connector needs — the exact
role, grants, and key-pair user documented in
[`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md) §5 — as Terraform, so a
customer runs `terraform apply` instead of hand-running the `ACCOUNTADMIN` SQL.

This is the **only** per-cloud difference in the connect flow: the
**`ABOM_READONLY`** role + its read-only grants and a **key-pair** scanner user.
No password is ever set; no write privilege is granted. The connector runs only
`SELECT`/`SHOW` over `ACCOUNT_USAGE`.

## What it creates

| Resource | Mirrors the SQL |
|----------|-----------------|
| `ABOM_READONLY` role | `CREATE ROLE ABOM_READONLY` |
| `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE` | `ACCOUNT_USAGE.*` + CIS checks |
| `MONITOR USAGE ON ACCOUNT` | `SHOW …` discovery |
| `USAGE ON WAREHOUSE <wh>` | compute to run read-only `SELECT`s |
| `ABOM_SCANNER` key-pair user | `CREATE USER … RSA_PUBLIC_KEY` (no password) |
| role → user grant | `GRANT ROLE ABOM_READONLY TO USER ABOM_SCANNER` |

The **private key never enters Terraform** — only the public key body is passed
in (`rsa_public_key`). No password is supported, by design.

## Provider auth (no secrets in `.tf`)

Configure the Snowflake provider via env / a Terraform variable; this module
ships no provider credential block. Run `terraform apply` with an
`ACCOUNTADMIN`-capable identity, e.g.:

```bash
export SNOWFLAKE_ORGANIZATION_NAME="MY_ORG"
export SNOWFLAKE_ACCOUNT_NAME="MY_ACCOUNT"
export SNOWFLAKE_USER="ADMIN_USER"
export SNOWFLAKE_AUTHENTICATOR="SNOWFLAKE_JWT"
export SNOWFLAKE_PRIVATE_KEY="$(cat /path/to/admin_key.p8)"
export SNOWFLAKE_ROLE="ACCOUNTADMIN"
```

## Usage

```hcl
provider "snowflake" {} # reads SNOWFLAKE_* env above

module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-snowflake"

  warehouse_name = "COMPUTE_WH"
  rsa_public_key = file("${path.module}/abom_key.pub.body") # PEM body, no headers
}
```

## After apply

```bash
export SNOWFLAKE_ACCOUNT="ORG-ACCOUNT"        # or LOCATOR.region.cloud
export SNOWFLAKE_USER="ABOM_SCANNER"          # terraform output user_name
export SNOWFLAKE_AUTHENTICATOR="snowflake_jwt"
export SNOWFLAKE_PRIVATE_KEY_PATH="/path/to/abom_key.p8"
agent-bom agents --snowflake
```

The private key stays on the scanner host — no shared secret transits or is
stored.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `role_name` | `ABOM_READONLY` | Read-only role name. |
| `user_name` | `ABOM_SCANNER` | Key-pair scanner user name. |
| `warehouse_name` | `COMPUTE_WH` | Warehouse to grant `USAGE` on. |
| `rsa_public_key` | — | PEM public-key body (no headers). Required; no password. |

## Outputs

`role_name`, `user_name`, `warehouse_name`, `granted_privileges`.
