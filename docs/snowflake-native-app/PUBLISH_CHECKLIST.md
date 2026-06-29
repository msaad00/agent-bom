# Native App → published — concrete gap checklist

Provider-side checklist for moving agent-bom from **dry-run packaging** to a
**listed Snowflake Native App**. Artifact design is largely complete; the gaps
are provider bootstrap, image publishing, live install proof, and Marketplace
approval.

**Package root:** [`deploy/snowflake/native-app/`](../../deploy/snowflake/native-app/)  
**Current version label:** `v0_89_2` (from `pyproject.toml` `0.89.2`)  
**Workflow:** [`.github/workflows/release-snowflake.yml`](../../.github/workflows/release-snowflake.yml)  
**Customer install:** [`INSTALL.md`](INSTALL.md)

---

## Ready (no blocker in artifact design)

- [x] `manifest.yml` — customer-bound references (read-only), EAIs default-off, pinned images
- [x] `scripts/setup.sql` — schema, health check, core SPCS service, opt-in scanner/MCP procs
- [x] `scripts/customer_grants_template.sql` — canonical GRANT examples
- [x] `scripts/network_policies.sql` + `scripts/auth_keypair_setup.sql` — templates
- [x] SPCS specs — API/UI default; scanner/MCP internal-only, opt-in
- [x] DCM modules `dcm/V001__core_schema.sql`, `dcm/V002__compliance_proc.sql`
- [x] Contract tests — [`tests/test_snowflake_native_app.py`](../../tests/test_snowflake_native_app.py)
- [x] Dry-run packaging workflow (`release-snowflake.yml`, default `dry_run: true`)
- [x] Draft provider docs — [`MARKETPLACE.md`](MARKETPLACE.md), [`INSTALL.md`](INSTALL.md)

---

## Gaps (ordered — do in this sequence)

### 1. Provider Snowflake account bootstrap

**Owner:** platform / release  
**Evidence when done:** SQL log or runbook commit showing package + image repo exist

- [ ] Create Snowflake **image repository** for four tags: `agent-bom`, `agent-bom-ui`, `agent-bom-scanner`, `agent-bom-mcp-runtime`
- [ ] Create **application package** `AGENT_BOM_PKG` (or org-standard name)
- [ ] Document provider account, role, and warehouse used for publish CI
- [ ] Configure GitHub environment `snowflake-marketplace` with secrets:
  - `SNOWFLAKE_ACCOUNT`, `SNOWFLAKE_USER`, `SNOWFLAKE_PRIVATE_KEY`
  - `SNOWFLAKE_APPLICATION_PACKAGE`

**Repo touchpoint:** add `docs/snowflake-native-app/PROVIDER_BOOTSTRAP.md` once steps are proven (optional follow-up).

### 2. Build and push versioned images to Snowflake registry

**Owner:** release  
**Evidence:** `SHOW IMAGES IN IMAGE REPOSITORY …` listing `v0_89_2` for all four images

- [ ] Build API image from [`deploy/docker/Dockerfile.snowpark`](../../deploy/docker/Dockerfile.snowpark)
- [ ] Build UI image from [`ui/Dockerfile`](../../ui/Dockerfile)
- [ ] Build scanner + MCP runtime images (same Dockerfiles with role-specific tags — document recipe)
- [ ] Push all four as `…/agent_bom_repo/<name>:v0_89_2` matching `manifest.yml`
- [ ] Automate in CI (today: manual per [`HOSTED_POC.md`](../HOSTED_POC.md) Snowflake stand-up §2)

**Blocker:** no workflow pushes to Snowflake `agent_bom_repo` today.

### 3. Compute pool + warehouse prerequisites (install docs)

**Owner:** docs + setup SQL  
**Evidence:** [`INSTALL.md`](INSTALL.md) includes pre-install SQL; clean-account install succeeds

`setup.sql` hardcodes `IN COMPUTE POOL consumer_pool` and `WAREHOUSE = 'COMPUTE_WH'`.
Install fails if the consumer has not provisioned these.

- [ ] Add **Pre-install** section to `INSTALL.md`:
  ```sql
  USE ROLE ACCOUNTADMIN;
  CREATE COMPUTE POOL IF NOT EXISTS consumer_pool
    MIN_NODES = 1 MAX_NODES = 1 INSTANCE_FAMILY = CPU_X64_S AUTO_RESUME = TRUE;
  GRANT USAGE ON COMPUTE POOL consumer_pool TO APPLICATION ROLE app_user;
  GRANT USAGE ON WAREHOUSE COMPUTE_WH TO APPLICATION ROLE app_user;
  ```
- [ ] Decide: keep hardcoded names vs manifest configuration refs
- [ ] Align `INSTALL.md` dev path version (`v0_85` → current `v0_89_2`)

### 4. DCM V001 wiring vs setup.sql drift

**Owner:** engineering  
**Evidence:** single schema source; upgrade path documented

- [ ] `setup.sql` executes only `dcm/V002__compliance_proc.sql` — **V001 never applied**
- [ ] Reconcile inline DDL in `setup.sql` with `V001` (`tenant_id`, `bound_references`, indexes)
- [ ] Either invoke V001 from setup or delete duplicate DDL and document DCM-only path

### 5. End-to-end private-preview install test

**Owner:** solutions / QA  
**Evidence:** signed checklist artifact (log + screenshots) in release notes or internal drive

Run in a **clean Snowflake account** (not provider dev account):

- [ ] `CREATE COMPUTE POOL` + warehouse grants (step 3)
- [ ] Install application package from staged `dist/agent-bom-snowflake-*.tgz`
- [ ] Bind references per [`customer_grants_template.sql`](../../deploy/snowflake/native-app/scripts/customer_grants_template.sql)
- [ ] Leave advisory EAIs disabled unless enrichment demo needed
- [ ] `CALL agent_bom.core.health_check();` → success
- [ ] `SHOW SERVICES IN APPLICATION agent_bom;` → `core.agent_bom_api` running
- [ ] Open default web endpoint (Next.js UI via SPCS)
- [ ] Optional: `CALL agent_bom.core.enable_scanner_service();` + smoke scan
- [ ] Customer smoke block from [`MARKETPLACE.md`](MARKETPLACE.md) — all green

**Blocker:** no recorded live install log in repo today.

### 6. Package validation CI on every release

**Owner:** release  
**Evidence:** workflow run URL attached to release

- [ ] Trigger `release-snowflake.yml` on release tags (today: `workflow_dispatch` only)
- [ ] Attach `dist/agent-bom-snowflake-*.tgz` artifact to GitHub Release

```bash
gh workflow run release-snowflake.yml -f dry_run=true
```

### 7. Enable live publish (remove intentional gate)

**Owner:** platform  
**Evidence:** `dry_run=false` workflow completes; package version in Snowflake

[`release-snowflake.yml`](../../.github/workflows/release-snowflake.yml) publish job **exits 1** with:
*"Snowflake CLI publish is intentionally gated until Marketplace listing approval"*.

- [ ] Implement `snow` CLI (or SQL) publish step in publish job
- [ ] Remove hard `exit 1` after Marketplace dry-run review
- [ ] Test `dry_run=false` against `private_preview` channel first

### 8. Marketplace listing submission

**Owner:** product / partnerships  
**Evidence:** listing ID, review ticket, approved channel

- [ ] Listing assets: icon, short/long description, category (Security and Governance)
- [ ] Data-boundary statement: customer account only; default egress off
- [ ] Update `INSTALL.md` marketplace one-liner (today: `INSTALL_FROM_MARKETPLACE('agent-bom')` TBD)
- [ ] Update [`MARKETPLACE.md`](MARKETPLACE.md) **Live publish status** from "Not enabled"

### 9. Streamlit vs Next.js UX decision

**Owner:** product  
**Evidence:** manifest documents primary dashboard path

- [ ] [`streamlit/dashboard.py`](../../deploy/snowflake/native-app/streamlit/dashboard.py) exists but is **not in manifest**
- [ ] Default UX is Next.js via SPCS (`default_web_endpoint: ui`) — confirm or wire Streamlit as fallback

### 10. Buyer-expectation doc for store parity

**Owner:** docs  
**Evidence:** site-docs link from INSTALL

- [ ] Cross-link [`site-docs/deployment/snowflake-backend.md`](../../site-docs/deployment/snowflake-backend.md) partial `SnowflakeStore` coverage so buyers know control-plane parity limits

---

## Exit criteria — "published"

All must be true before calling the Native App **published**:

1. Four images at current version tag live in provider Snowflake image repo
2. Private-preview install checklist (step 5) passed in a clean account
3. `release-snowflake.yml` with `dry_run=false` succeeds to `private_preview`
4. Marketplace listing approved (or explicit private listing for named accounts)
5. `INSTALL.md` install command and version tags match `manifest.yml`
6. DCM/setup drift (step 4) resolved or documented with upgrade notes

---

## Quick commands

```bash
# Validate package locally
gh workflow run release-snowflake.yml -f dry_run=true

# Manual tarball (version from pyproject.toml → v0_89_2)
mkdir -p dist
tar -czf dist/agent-bom-snowflake-v0_89_2.tgz -C deploy/snowflake/native-app .

# Customer smoke (after install)
# snow sql -q "CALL agent_bom.core.health_check();"
```

See also [`docs/ROADMAP_SAAS.md`](../ROADMAP_SAAS.md) for how Phase 1 fits between the demo VM and public SaaS.
