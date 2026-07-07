# Publication Policy — Public Repo vs Operator-Private

This repository is **public OSS**. The split below matches how mature security
products (Grafana, ClickHouse, LangChain OSS) ship code and docs while keeping
production custody private.

## Public in this repository

- Source code, tests, Helm/Docker/compose, and integration assets
- User and operator documentation (`README.md`, `site-docs/`, deployment guides)
- Security artifacts: `SECURITY.md`, threat model, architecture, pentest scope
- Rotation **framework**: API routes, env var names (`*_LAST_ROTATED`,
  `*_ROTATION_DAYS`), adapter command templates, default intervals
- Example configs with placeholders (`.env.example`, `*secret.example.yaml`,
  `REPLACE_ME_*` Helm values)
- Illustrative timestamps in docs (for example `2026-04-26T00:00:00+00:00`) —
  not live production rotation state

Rotation procedures and env var names are public by design. Posture endpoints
(`GET /v1/auth/secrets/lifecycle`, `GET /v1/auth/secrets/rotation-plan`) are
admin-authenticated at runtime and return metadata only
(`secret_values_included=false`). See
[ENTERPRISE_SECURITY_POSTURE.md](ENTERPRISE_SECURITY_POSTURE.md#secrets-lifecycle).

## Operator-private (never commit)

- Secret **values**: API keys, HMAC/signing keys, SCIM bearer tokens, database
  passwords, TLS private keys, cloud credentials
- Live `*_LAST_ROTATED` values for production or hosted POC deployments
- Bootstrap output (for example `/tmp/agent-bom-customer0-admin.key` from
  `scripts/deploy/mint_hosted_admin_key.py`)
- Customer names, contracts, pricing, named buyer references
- Internal rotation calendars tied to real infrastructure (“rotate SCIM token
  every N days on cluster X”)
- Real change-ticket or cloud audit evidence from production rotations
- Unfixed vulnerability write-ups before the GitHub Security Advisory window

Store operator-private material in a separate private ops repo, vault, or
GitHub Environments — not in this tree.

## Customer VPC (their boundary)

Customers run self-hosted control planes in their own cloud, database, identity,
and audit boundary. Their scan data, graphs, API keys, and rotation timestamps
belong to them — not to this repository.

## Pre-commit checklist

Before pushing deploy or ops changes:

1. No `.env` files except `.env.example`
2. No files under `deploy/secrets/` except `*.example` and README
3. No minted keys, kubeconfigs, or connection strings with real hostnames/ARNs
4. Doc timestamps are clearly examples, not copied from a live environment
5. Security issues reported via
   [GitHub Security Advisories](https://github.com/msaad00/agent-bom/security/advisories/new),
   not public issues

## Related docs

- [PRODUCT_BOUNDARIES.md](PRODUCT_BOUNDARIES.md) — shipped lanes vs roadmap
- [ENTERPRISE_SECURITY_POSTURE.md](ENTERPRISE_SECURITY_POSTURE.md) — buyer-facing controls
- [SECURITY.md](../SECURITY.md) — vulnerability reporting
