# Connecting Clouds to agent-bom

How agent-bom reads, ingests, and integrates AWS, Azure, and Snowflake — and
**why** every step is read-only, least-privilege, and zero-trust by design.

agent-bom is a **scanner, not a platform**. It connects to a cloud with the
least privilege that still lets it *see*, reads inventory and posture through
control-plane list/get APIs only, normalizes what it sees into one graph, and
emits findings. It never writes, never reads secret contents, never moves data
out of your account, and never stores a password.

---

## 1. The approach (why it is safe to point at production)

| Principle | What it means here |
|-----------|--------------------|
| **Read-only** | Only `List*` / `Describe*` / `Get*` (AWS), `list` / `get` ARM (Azure), and `SELECT` / `SHOW` over `ACCOUNT_USAGE` (Snowflake). No create/update/delete, ever. |
| **Least privilege** | A single read-only managed role per cloud (AWS `SecurityAudit`, Azure `Reader`/`Security Reader`, Snowflake `ABOM_READONLY`). Nothing broader. |
| **Zero trust / no passwords** | Short-lived tokens, key-pairs, or federated identity only. No long-lived password is ever accepted (Snowflake password auth is deprecated and warns). |
| **No data exfiltration** | Secret *metadata* is read (a secret exists, when it rotated) but never secret *values*. No object/blob/row data is read. Errors are sanitized before display. |
| **Customer-owned** | Findings stay in your environment. agent-bom has no phone-home; the discovery envelope on every payload records `ScanMode.CLOUD_READ_ONLY` and the exact permissions used. |
| **Accurate** | Coverage is provable: a guard test asserts every SDK client used is real; misconfigurations converge into the same findings stream and exit-code gate as vulnerabilities, so nothing is "shown but unenforced". |

All three connectors are **opt-in and default-off**, gated by per-provider env
flags. With the flags unset, agent-bom does zero cloud network I/O.

**One pattern, not three.** The *only* thing that differs per cloud is the one
line that mints the read-only role — because each platform's grant primitive is
different (AWS IAM policy, Azure RBAC role, Snowflake role+grant). Everything
else is identical: enable with `AGENT_BOM_<PROVIDER>_INVENTORY=1`, authenticate
with the cloud's own identity (never a secret handed to agent-bom), get the same
graph and findings out. This mirrors how connector-based scanners work — a
per-cloud role template, one uniform flow around it.

---

## 2. End-to-end: how data flows

```
  connect            discover               normalize            integrate            enforce
 (read-only      (control-plane          (CloudResource +      (one unified         (findings +
  credential) ─▶  list/get APIs)   ─▶     identity model)  ─▶   graph: nodes    ─▶   --fail-on-
                  per provider            + discovery            + edges)             severity gate)
                                          envelope
```

1. **Connect** — the connector resolves a credential from the standard chain for
   that cloud (never from agent-bom config). If no credential resolves, the
   provider is skipped with a warning; a scan never fails because a cloud is
   unreachable.
2. **Discover** — each provider runs a set of read-only discovery functions
   concurrently. Every function is wrapped so one failing API (or a missing
   optional SDK) degrades to a warning instead of sinking the scan.
3. **Normalize** — raw responses become a provider-neutral `CloudResource` /
   identity model, each stamped with a **discovery envelope**
   (`ScanMode.CLOUD_READ_ONLY`, `permissions_used`, redaction status).
4. **Integrate** — the graph builder projects resources, identities, and their
   relationships into one `UnifiedGraph` (`CONTAINS` hierarchy, `HAS_PERMISSION`
   for CIEM, `EXPOSED_TO` for network reach, `STORES` for data paths). The same
   builder fuses CNAPP overlays and attack paths across clouds.
5. **Enforce** — CIS benchmark failures and graph toxic-combinations are
   converted to `Finding` objects that flow into `report.to_findings()`, so
   `--fail-on-severity` can fail a build on a real misconfiguration or exposure,
   not just draw it on a graph.

This is the same code path for the CLI and the API, so both surfaces produce
identical results.

---

## 3. AWS — connect in two steps

**Grant** (read-only, managed): attach the AWS-managed **`SecurityAudit`** policy
(or `ViewOnlyAccess`) to the principal agent-bom will use. That single policy
covers every action the scanner needs.

**Authenticate** via the standard boto3 chain — pick one, no secrets in agent-bom:
- a named profile (`AWS_PROFILE`), or
- env keys (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`), or
- an instance/EKS/ECS role, or SSO.

```bash
export AGENT_BOM_AWS_INVENTORY=1            # opt-in (per-provider, symmetric)
export AWS_PROFILE=abom-readonly            # SecurityAudit-attached profile
agent-bom agents --preset enterprise --aws
```

**What it reads** (all read-only): S3, EC2 + security groups, IAM
roles/users/policies and the permission edges between them, RDS, DynamoDB,
Lambda, EKS, ELB/ALB/NLB, VPCs, KMS, Secrets Manager (metadata only), CloudFront,
ECR, Redshift, SNS/SQS — plus AWS **Organizations** (OU tree → accounts → SCPs)
for multi-account estates, and **60 CIS checks**.

**Why read-only is enough:** the connector calls only `List*`/`Describe*`/`Get*`
and `sts:GetCallerIdentity`. The exact action set is declared as permission
constants in `cloud/aws_inventory.py` (`_AWS_*_PERMISSIONS`) and
`cloud/aws_organizations.py` (`_AWS_ORG_PERMISSIONS`). Secret *values* are never
read — only existence and rotation state.

**Secure-by-default provisioning** (`deploy/terraform/connect-aws`): the read-only
role gets a **unique, non-guessable name** (`abom-readonly-<random hex>`) and an
**always-enforced, high-entropy `sts:ExternalId`** — generated automatically when
you don't supply one and surfaced via a *sensitive* `external_id` output. The
confused-deputy condition can never be silently omitted, and a predictable
principal name can't be squatted or targeted. Both have override variables for
operators who need a fixed name or a BYO External ID.

**One SDK, proven current:** AWS support uses a single dependency (`boto3`, the
`aws` extra). A guard test (`tests/test_aws_boto3_client_coverage.py`) scrapes
every `.client("…")` the code uses and asserts each is a real service in the
pinned boto3 — so a typo or too-old pin fails CI, not production.

---

## 4. Azure — connect with the credential you already have

**Grant** (read-only, built-in): assign **`Reader`** (and **`Security Reader`**
for Defender posture) at the subscription, or at the **tenant root management
group** to cover every subscription at once.

**Authenticate** via `DefaultAzureCredential` — no password, pick one:
- `az login` (cached CLI token), or
- a service principal with a **certificate** (not a secret), or
- a system/user-assigned **managed identity**, or
- workload identity federation (Kubernetes).

```bash
export AGENT_BOM_AZURE_INVENTORY=1
export AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1   # fan out across the tenant
agent-bom agents --preset enterprise --azure
```

**What it reads:** storage accounts, VMs, AKS, App Services, disks, NSGs,
managed identities + **RBAC role assignments** (CIEM edges), Key Vaults,
container registries, Cosmos/SQL/PostgreSQL/MySQL, VNets/public-IPs/load
balancers/Front Door/API Management, Event Hubs/Service Bus/Redis,
**management groups** for hierarchy, and **96 CIS checks**.

**Tenant scale (zero trust at scale):** with `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS=1`
the connector walks the management-group tree, enumerates every subscription,
and scans each independently — partitioned in the graph by account so thousands
of subscriptions stay separable. A defensive `AGENT_BOM_AZURE_MAX_SUBSCRIPTIONS`
cap (default 500) bounds blast radius.

**SDK fragility, handled:** Azure SDKs are per-service distributions, so each is
imported under `try/except ImportError` and degrades to a warning if absent —
one missing package never crashes a scan.

**Secure-by-default provisioning** (`deploy/terraform/connect-azure`): the
optional keyless **federated identity credential** is pinned to an exact
**issuer + subject + audience** (`api://AzureADTokenExchange`). The plan fails if
the subject is empty or contains a wildcard, so only one specific external
workload can exchange a token for the scanner principal — never a wide-open
trust. The GCP module (`deploy/terraform/connect-gcp`) is locked the same way:
Workload Identity Federation cannot be enabled without a scoped
`attribute_condition`, pinned audiences, and a specific `principalSet`, and the
service account gets a unique, non-guessable name.

---

## 5. Snowflake — connect with a key-pair, never a password

**Grant** (read-only role + key-pair user). Run once as `ACCOUNTADMIN`:

```sql
USE ROLE ACCOUNTADMIN;
CREATE ROLE IF NOT EXISTS ABOM_READONLY;

-- ACCOUNT_USAGE powers inventory + the CIS benchmark
GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE ABOM_READONLY;
-- account/warehouse visibility for SHOW-based discovery (tasks, streams, stages…)
GRANT MONITOR USAGE ON ACCOUNT TO ROLE ABOM_READONLY;
GRANT USAGE ON WAREHOUSE COMPUTE_WH TO ROLE ABOM_READONLY;   -- swap to your WH

-- key-pair scanner user (no password)
CREATE USER IF NOT EXISTS ABOM_SCANNER
  DEFAULT_ROLE = ABOM_READONLY
  DEFAULT_WAREHOUSE = 'COMPUTE_WH'
  RSA_PUBLIC_KEY = '<PEM public key, no headers>';
GRANT ROLE ABOM_READONLY TO USER ABOM_SCANNER;
```

**Why each grant — mapped to what it unlocks:**

| Grant | Unlocks |
|-------|---------|
| `IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE` | `ACCOUNT_USAGE.*` and `INFORMATION_SCHEMA.*` — object/lineage graph, grants, auth posture, login anomalies, exfil tags, CIS checks |
| `MONITOR USAGE ON ACCOUNT` | `SHOW …` commands — warehouses, databases/schemas, tasks, streams, pipes, stages, shares, integrations, external/iceberg tables |
| `USAGE ON WAREHOUSE` | the compute to run the read-only `SELECT`s |

**Authenticate** with the matching private key — no password ever:

```bash
export SNOWFLAKE_ACCOUNT="ORG-ACCOUNT"      # or LOCATOR.region.cloud, e.g. xy12345.ca-central-1.aws
export SNOWFLAKE_USER="ABOM_SCANNER"
export SNOWFLAKE_AUTHENTICATOR="snowflake_jwt"
export SNOWFLAKE_PRIVATE_KEY_PATH="/path/to/abom_key.p8"
agent-bom agents --snowflake
```

**Why key-pair over password:** key-pair (RSA JWT) means no shared secret ever
transits or is stored; the private key stays on the scanner host. Password auth
is deprecated in the connector and emits a runtime warning. SSO
(`externalbrowser`) and OAuth are also supported for interactive use.

**What it reads:** the **AI-BOM** (Cortex agents, MCP servers, Snowpark
packages, UDFs/procedures, notebooks, Streamlit apps); the object + lineage
graph (tables/views + `OBJECT_DEPENDENCIES`, grants, role memberships); data-exit
surface (outbound shares, external stages, sensitivity-tagged objects); per-user
auth posture (MFA / key-pair / password, network policies); login anomalies
(impossible travel, IP spread, failed-login bursts); warehouses/databases/schemas;
pipeline objects (tasks/streams/pipes); account integrations; iceberg/external
tables; and **14 CIS checks**.

**Honest caveats (accuracy):** `ACCOUNT_USAGE` views have ingestion latency
(minutes to hours), so freshly-created objects and tags may lag one scan.
Discoveries that need a grant you didn't give degrade to empty rather than error
— so apply the full grant block above for complete coverage.

---

## 6. Security guarantees, restated

- **No writes.** No connector calls a create/update/delete API in any cloud.
- **No secret contents.** Secret/Key-Vault/Secrets-Manager *metadata* only.
- **No data movement.** No object, blob, queue, or table-row data leaves your
  account; agent-bom reads catalog and posture, not payload.
- **No phone-home.** Results are written where you point them. The discovery
  envelope on every payload records the read-only scan mode and the exact
  permissions exercised, so an auditor can verify the blast radius.
- **Sanitized errors.** Connector exceptions pass through a central sanitizer
  before they reach logs or output, so a malformed credential can't leak.
- **Secure-by-default identities.** The Terraform connect modules mint the
  read-only identity so it is **unique, unguessable, and not exploitable**: a
  randomized principal name (anti-squatting), a mandatory high-entropy AWS
  `ExternalId` (confused-deputy defense), and federation that is locked to a
  specific issuer + subject + audience (no wide-open trust). Overrides exist for
  operators who need fixed values; only the *defaults* changed, so existing
  configs that pin a name/External ID still apply unchanged.

> **Threat note (provisioning).** Two classic IAM pitfalls these defaults close:
> the **confused-deputy** problem — where a third party that learns your role
> ARN tricks the shared scanner account into assuming it without an ExternalId
> guard — and **name-squatting / targeting** of a predictable principal name.
> Wide-open federation (an OIDC trust with no subject/condition) is the cloud
> equivalent: any token from the issuer could impersonate the read-only
> identity. The modules now make the secure path the default one.

---

## 6a. Audit-trail behavioral edges — no new role

Setting `AGENT_BOM_AUDIT_TRAIL=1` reads the security-relevant slice of each
cloud's native audit trail (AWS CloudTrail, Azure Activity Log, GCP Cloud Audit
Logs) into **behavioral graph edges** ("who *did* reach what"). It is opt-in,
read-only, and drops the raw events — logs stay in your account.

**It needs no new IAM role.** Audit-trail reuses the **same** read-only connect
role you already created:

| Cloud | Existing read-only role | Audit read | Already covered? |
|-------|-------------------------|------------|------------------|
| AWS   | `SecurityAudit` (+ `ViewOnlyAccess`) | `cloudtrail:LookupEvents` | **Yes — zero new permission.** `LookupEvents` is in the AWS-managed `SecurityAudit` policy. |
| Azure | `Reader` / `Security Reader` | `Microsoft.Insights/eventtypes/values/read` | Yes in standard setups — sits inside the built-in `Reader` role. |
| GCP   | `roles/viewer` | `logging.logEntries.list` | Yes in standard setups — sits inside `roles/viewer`. |

Net: turning on audit-trail behavioral edges costs **no new role** and, in
standard setups, **no new permission**.

> **The one exception is the disk side-scan.** Agentless EBS side-scan
> (`AGENT_BOM_SIDESCAN=1`) is the single deliberately non-read-only
> capability, and it is the *only* one that needs a **separate, scoped snapshot
> role** (`deploy/terraform/connect-aws-sidescan`) distinct from the read-only
> scanner role, plus an in-account collector instance. Audit-trail does not.

---

## 6b. Agentless EBS disk side-scan (opt-in, scoped role)

The disk side-scan snapshots a target EBS volume, attaches a temp volume to an
**in-account collector** instance, mounts it read-only, and returns a
metadata-only result — package SBOM, matched CVEs, and secret *type/location*
(never values, never file contents). Snapshot → volume → mount are always torn
down in a guaranteed cleanup; a pre-run sweep reaps anything a prior crash
stranded. No disk image or block data leaves the account.

It is OFF unless `AGENT_BOM_SIDESCAN=1`. Run it from the collector (or any host
with the scoped snapshot role) with:

```bash
AGENT_BOM_SIDESCAN=1 agent-bom cloud side-scan \
  --volume-id vol-0abc123 \
  --collector-instance-id i-0def456 \
  --availability-zone us-east-1a \
  --region us-east-1
```

Use `--instance-id i-...` instead of `--volume-id` to scan every EBS volume
attached to an instance. `--no-secrets` returns SBOM + CVEs only;
`--no-sweep-orphans` skips the pre-run stranded-snapshot sweep. With the flag
unset the command prints how to enable it and exits non-zero — it never starts a
snapshot implicitly.

---

## 7. Why it scales and stays accurate

- **Scale:** AWS Organizations and Azure management-group fan-out discover the
  whole estate; the graph partitions by account so multi-account/multi-tenant
  estates stay separable, with explicit caps to bound a run.
- **Alignment:** every datum a connector collects is wired end-to-end —
  data model → graph nodes/edges → JSON output → CLI/API → tests — so nothing is
  "collected but dropped". A guard test keeps the AWS SDK surface honest.
- **Enforcement:** CIS misconfigurations and graph toxic-combinations become
  first-class `Finding`s, so `--fail-on-severity` fails a pipeline on a real
  exposure — posture is enforced, not just visualized.

> Pointing agent-bom at a new cloud is a managed read-only role plus a few lines
> of env. That is the whole integration surface — by design.
