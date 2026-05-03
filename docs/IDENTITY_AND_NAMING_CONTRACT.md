# Identity and Naming Contract

agent-bom follows one principle for every name, value, and configuration knob:

> **The system owns the vocabulary. The customer owns the identity.**

This page is the single source of truth for what's fixed, what's customer-controlled, and what's a hybrid default. Operators reading this page should never have to reverse-engineer the contract from source code or per-endpoint route docs.

---

## What's fixed (system vocabulary)

These are part of the public API contract. They're case-sensitive, closed enums, and never change without a major version bump. Shipping a typo here is a misconfiguration that fails at boot or denies traffic — not silently downgrades.

### Roles

`src/agent_bom/rbac.py:31` — closed three-value enum. No other roles exist in agent-bom.

| Role | Use |
|---|---|
| `admin` | Full control plane — protected writes, key/policy/fleet/tenant management |
| `analyst` | Contributor — runs scans, manages sources, drives exception workflows |
| `viewer` | Read-only — inventory, findings, graph, posture, audit |

`AGENT_BOM_DEFAULT_ROLE` and `AGENT_BOM_API_KEYS` entries must use one of these literal values. A bad value raises `InvalidRoleError` at boot — silent fallback to `viewer` is no longer accepted.

### Permission actions

`src/agent_bom/rbac.py:38` — closed set. Endpoints declare their required action; routes that ask for an unknown action are denied with `Unknown action — denying by default` in the log.

`scan`, `read`, `fleet_write`, `fleet_read`, `policy_write`, `policy_read`, `exception_create`, `exception_approve`, `exception_read`, `alert_write`, `alert_read`, `audit_read`, `sla_write`, `sla_read`, `config`.

### Compliance framework slugs

`src/agent_bom/compliance_hub.py:33` and `src/agent_bom/constants.py:589` — 14 canonical slugs. The dashboard renders by slug; an unknown slug becomes a blank framework card. Locked in by `tests/test_compliance_hub_cross_format.py::test_no_adapter_emits_unknown_framework_slugs`.

`owasp-llm`, `owasp-mcp`, `owasp-agentic`, `atlas`, `nist`, `nist-csf`, `nist-800-53`, `fedramp`, `eu-ai-act`, `iso-27001`, `soc2`, `cis`, `cmmc`, `pci-dss`.

### Environment variable names

The variable **names** are a stable public contract. The values are yours.

| Variable | Purpose |
|---|---|
| `AGENT_BOM_API_KEY` | Single primary API key for the API/dashboard |
| `AGENT_BOM_API_KEYS` | Multi-key with role mapping: `key1:admin,key2:analyst,...` |
| `AGENT_BOM_DEFAULT_ROLE` | Fallback role when no key matches (`admin`/`analyst`/`viewer`) |
| `AGENT_BOM_DB` | SQLite database path (single-node persistence) |
| `AGENT_BOM_POSTGRES_URL` | Postgres connection URL (multi-replica persistence) |
| `AGENT_BOM_SCIM_BEARER_TOKEN` | SCIM endpoint bearer token |
| `AGENT_BOM_TRUST_PROXY_AUTH` / `AGENT_BOM_TRUST_PROXY_AUTH_SECRET` | Trusted proxy attestation |
| `AGENT_BOM_AUDIT_HMAC_KEY` | Audit log signing key (production must set) |
| `AGENT_BOM_RATE_LIMIT_KEY` | Rate-limit signing key (production must set) |

These names will not change. The variable's *value* is yours to set however your secret manager / orchestrator wires it.

### Format strings

`sarif`, `cyclonedx`, `csv`, `json` — accepted by `POST /v1/compliance/ingest` and the CLI. Anything else returns 400.

### Reserved tenant identifiers

`src/agent_bom/platform_invariants.py:RESERVED_TENANT_IDS` — agent-bom owns this small namespace; customer tenant IDs cannot collide.

`admin`, `analyst`, `viewer`, `system`, `__system__`.

These are the role/permission vocabulary plus the system sentinels — a customer-supplied tenant ID matching a role name would shadow our enums in URLs and audit logs. Customer-supplied IDs (HTTP headers, JWT claims, SCIM payloads) that match any reserved name are rejected with `400 ReservedTenantIdError`.

`default` is **intentionally not reserved**. It's the canonical single-tenant value; the system fallback bucket and any customer-supplied `default` resolve to the same bucket — single-tenant pilots and tests can keep using it.

---

## What's customer-controlled (your identity)

These belong to your namespace. Pick whatever your team's vocabulary uses; agent-bom won't impose ours.

### API key values

`api/auth.py:create_api_key` mints `abom_<32-byte-token>` for keys we generate. Customer-supplied keys via `AGENT_BOM_API_KEYS` can be any string ≥ 32 characters. Below the entropy floor, `configure_api_keys` raises `ApiKeyEntropyError` so a `key1:admin` shortcut value can't slip into production.

### Tenant identifiers

Any non-reserved string is a valid tenant ID. Recommended forms:
- A UUID
- `org-<slug>`
- Your tenant identity from your IdP (Okta org slug, Azure AD tenant ID, etc.)

Validated at API ingress via `validate_customer_tenant_id`. Internal callers that genuinely want the system fallback don't supply a value — `normalize_tenant_id` returns `default` for empty/missing input.

### API key display names, descriptions, finding titles, custom labels

Free-form text. agent-bom never imposes a naming convention on these; they're for your humans.

### SCIM userName, externalId, group displayName

Whatever your IdP sends.

---

## Hybrids (defaults you can override)

Best-of-both-worlds onboarding: works without configuration, accepts your override.

| Surface | Default | How to override |
|---|---|---|
| API key | None — non-loopback binds fail closed | `AGENT_BOM_API_KEY` or `AGENT_BOM_API_KEYS` |
| Tenant ID | `default` (system fallback bucket) | Any non-reserved string at ingress |
| Default role | `viewer` (least privilege) | `AGENT_BOM_DEFAULT_ROLE` |
| Database backend | In-memory (ephemeral) | `AGENT_BOM_DB` (SQLite) or `AGENT_BOM_POSTGRES_URL` (Postgres) |
| Audit HMAC key | Ephemeral random (not durable across restarts) | `AGENT_BOM_AUDIT_HMAC_KEY` for production |

---

## Why the contract is shaped this way

**Closed enums for code-path identifiers.** Roles, actions, and slugs map to code paths. If a customer can rename them, integrations break across versions, security policies become unauditable, and the compliance dashboard can't render. Closed enums are the only shape that survives long-term.

**Free-form values for identity.** API keys, tenant IDs, and display names belong to *you*. Forcing customers to use agent-bom-flavored names is hostile and signals "this product was designed for a single deployment." Free-form values respect customer namespace + vocabulary.

**Hybrid defaults for onboarding.** Day-one customers get a working system without filling in 12 environment variables. Defaults are always the least-privileged / least-surprising / most-ephemeral option, and every default is overridable.

**Reserved namespace for system buckets.** A tiny set of names (five total — three role names plus two system sentinels) is reserved so customer-supplied identifiers can't shadow our internal vocabulary. Any name not in `RESERVED_TENANT_IDS` is yours, including `default`.

---

## Operator quick reference

- **Naming a tenant?** Anything except `admin`, `analyst`, `viewer`, `system`, `__system__`. `default` is fine — it just shares a bucket with the system fallback.
- **Wiring an API key?** ≥ 32 chars; we'll reject shorter at boot.
- **Setting a default role?** One of `admin`/`analyst`/`viewer` exactly; case-sensitive; bad value raises at boot.
- **Renaming an env var in your secret manager?** Doesn't matter — agent-bom reads `os.environ.get('AGENT_BOM_*')` by literal name. Map your secret to the agent-bom variable name in your manifest.
- **Customizing role names to match your IdP?** You can't. agent-bom roles are a closed three-value enum. Map your IdP's roles into our enum at the proxy layer.
