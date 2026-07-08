# Changelog

All notable changes to agent-bom are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versions follow [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Fixed
- **git-SHA advisory false positives (offline scan)** — the local `db/lookup`
  matcher no longer conservatively reports advisories whose only bounds are git
  commit SHAs (OSS-Fuzz / OSV-2022-* rows) against concrete semver versions;
  such rows are now classified `uncomparable` rather than `unknown`, so e.g.
  `pillow==11.0.0` stops drawing `OSV-2022-1074` / `OSV-2022-715`. Genuine semver
  in-range/past-fix matching and mixed SHA-plus-semver sibling rows are
  unaffected.
- **Malicious packages missing from CSV/Parquet export** — vuln-less
  malicious/typosquat packages (synthesized findings) now appear in the CSV and
  Parquet exports even when CVE findings are present, matching JSON/SARIF, with
  `is_malicious` and `malicious_reason` populated.

## [0.94.0] - 2026-07-08

Minor release shipping the post-0.93.5 audit/security batch, cloud and runtime
hardening, identity/SCIM fixes, CIS fail-closed coverage, and CI evidence
improvements for self-hosted control planes.

### Security / audit
- **CIS fail-closed** — ~25 checks report ERROR (not PASS) when per-resource reads
  are denied; strict GRC coverage mode for partial permission denial (#3691,
  #3695).
- **MCP ingest authz** — `ingest_external_scan` gated as a destructive write with
  admin/scope checks (#3692).
- **Shield runtime** — fail-closed defaults, credential redaction in proxy paths,
  SSRF guard on egress URLs (#3699, #3706).
- **SCIM / session** — PATCH remove/add semantics, audit-log viewer RBAC, session
  logout hardening, auto-bind SCIM subject on API key issuance (#3701, #3705).
- **CodeQL / export hygiene** — redacted JSON at formatter boundary; clear-text
  logging and stack-trace exposure fixes on scan stdout and tenant export
  (#3717, #3675).
- **Audit chain** — signed checkpoint detects tail truncation (#3700).

### Cloud / inventory
- **Full cloud coverage** — GCP/AWS pagination, Lambda package fetch, container
  deep-scan, Key Vault CIS fixes, Lambda on by default (#3634–#3636, #3706).
- **Ingest scale** — chunked `reconcile_absent` avoids bind-variable overflow on
  large batches (#3693).

### Platform / API
- **DB-aware `/readyz`** — readiness reflects database connectivity; firewall
  policy reload fails closed on error (#3707).
- **`/v1` router mount** — centralized API versioning foundation without wire
  contract changes (#3715).
- **Env aliases** — canonical deployment/CORS/Vault/ServiceNow env names with
  regenerated `ENV_VARS.md` (#3713); warn on unparseable bool/int/float env
  values (#3711).

### Output / CI evidence
- **SARIF fingerprints** — `partialFingerprints` for GitHub code-scanning dedup
  (#3712).
- **Malicious findings** — vuln-less malicious packages synthesized end-to-end in
  exports (#3694).
- **SARIF/JSON parity** — finding-count alignment, `--reproducible` timestamps,
  `/dev/null` exit semantics (#3645).
- **Scale-ready HTML** — tabbed, paginated report for large estates (#3637).

### Runtime / graph / data
- **Graph performance** — bounded snapshot stats, rollup orphans, deep-offset cap
  (#3669); drift-as-UI lens (#3649).
- **DB maintenance** — generic RANGE-partition retention rollover (#3657); hub
  read perf fixes (#3654).
- **Iceberg / ClickHouse** — catalog export and findings-ingest paths (#3648,
  #3650).

### MCP / developer experience
- **MCP catalog drift guard** — `@mcp.tool` names must match `_SERVER_CARD_TOOLS`
  set equality (#3675).
- **CLI scan UX** — unified terminal sections, deduped CIS output, tiered
  `--help` behind `--help-all` (#3633, #3672).
- **`make preflight`** — local drift gate for OpenAPI, schemas, and release
  consistency (#3702).

### Docs / deploy
- **Doc consolidation** — stage-1 hub structure for duplicate deploy/product
  clusters (#3704).
- **Deployment READMEs** — raw Kubernetes and Snowflake deploy paths (#3720;
  Snowflake README in #3721 when merged).
- **How-it-works** — canonical deployment matrix and editions page (#3668).

### Also in this release line (since 0.93.5)
- Endpoint-agent Phase 0 hardware-backed device identity (#3646).
- LLM enrichment harness maturity (#3639).
- Swift reachability tail precision (#3656).
- Stricter mypy phase 1 for models + core API (#3655).
- Test layout: `tests/cloud/`, `tests/api/` grouping (#3716, #3718).

## [0.93.5] - 2026-07-07

Patch release closing the post-#3624 audit queue, hardening demo/hosted POC
safety, and documenting public-repo custody boundaries before customer cloud
connect.

### Security / audit fixes
- **PHP/Swift reachability** — mask comments and string literals before call-site
  extraction so CVE reachability cannot be over-claimed from prose (#3626).
- **GCP Cloud SQL inventory** — paginate `nextPageToken` so public instances past
  page 1 are not dropped (#3626).
- **OAuth AS issuer** — honor `X-Forwarded-Host` only when
  `AGENT_BOM_TRUST_PROXY_AUTH=1` (#3626).
- **Malicious findings parity** — `is_malicious` / `malicious_reason` in CSV,
  Parquet, and SARIF; `--fail-on-malicious` gates typosquat and dependency
  confusion packages (#3626).
- **Remediation guidance** — suppress downgrade advice when forward fixed version
  is null (#3626).
- **Demo safety** — default `AGENT_BOM_NO_AUTH_ROLE=viewer`; hosted POC overlay
  sets `AGENT_BOM_DEMO_ESTATE=1` (#3624, #3626).
- **Compliance hub in-memory cursor** — align descending `last_seen` tie-break
  with SQL keyset pagination (#3626).
- **Credential ref `/test`** — validate `external_ref` shape and ambient provider
  probe instead of marking configured without checks (#3626).

### Cloud / inventory hardening
- **EBS side-scan** — paginate volume discovery and orphan snapshot sweeps
  (#3626).
- **WAFv2** — paginate `list_web_acls` and `list_resources_for_web_acl`
  (#3626).
- **Trivy CVSS** — honor redhat, amazon, and oracle vendor CVSS sources
  (#3626).
- **Severity policy** — rank `info` above `none` in policy-order comparisons
  (#3626).
- **SCIM deprovision** — revoke rotation replacement keys; match `userName` on
  `scim_subject_id` (#3624, #3626).

### Docs / positioning
- **`docs/PUBLICATION_POLICY.md`** — public OSS vs operator-private custody
  (secrets, rotation timestamps, hosted bootstrap output).
- Remove competitor names from deploy copy and NHI OpenAPI descriptions.
- Label `docs/audits/` as historical engineering records.

### Scale / ops
- **`scripts/bench/agent_bom_scale_bench.py`** — stdlib scale bench for live API
  + Postgres smoke (#3626).
- Skip `vendor/` trees in Python AST analysis (#3626).

### Also in this release line (since 0.93.0)
- UI product-proof screenshot refresh (#3625).
- GLM/Zhipu inventory and BYOM quickstart (#3623).
- Deploy quickstart, unified install script, and intake diagrams (#3621).

## [0.93.0] - 2026-07-06

Release deepens reachability proof, evidence ingest parity, and the unified
`Finding` read path — while hardening API scale, lifecycle, and operator docs
for self-hosted control planes.

### Reachability / blast radius
- **Multilanguage symbol join** for npm, Go, PyPI (AST), plus Java, Rust, NuGet,
  Ruby, and Gradle-only Java (conservative regex/manifest proof).
- **Symbol reach → triage and VEX**: unreachable symbol evidence feeds
  `effective_reach` scoring and auto-`not_affected` VEX suggestions (#3577).
- **Python symbol reach** exported in JSON/SARIF findings; delta-stream snapshots
  include symbol-reach material fields (#3571, #3573).
- **Advisory context** enrichment (CWE/CVE/CPE) at symbol-join build time (#3576).

### Evidence intake
- **SARIF external-scanner ingest** wired into `detect_and_parse` and
  `agent-bom agents --external-scan` for full scan depth (#3585).
- **CSAF and CycloneDX VEX** documents load through `load_vex` alongside OpenVEX
  (#3586).
- **`docs/INGEST_PATHS.md`** documents push vs `--external-scan` tradeoffs,
  Trivy/Grype/SARIF paths, and VM/registry first-command flows (#3587).

### Finding model / outputs
- **Markdown, PDF, and SARIF CVE loops** migrated to the unified `Finding` stream
  (#3570, #3574, #3578).
- **JSON/HTML CVE tables** migrated to `cve_findings()` (#3588).
- **Mermaid and graph topology** exports read CVE paths from the unified
  `Finding` stream (#2918).
- **Exposure paths** flow through `Finding` in JSON/HTML/SARIF.
- **VEX on Finding stream** with API `external_scan` / `vex` scan parity and SARIF
  VEX properties (#3589).
- **Registry verified badge** in default JSON MCP server rows and CLI dependency
  tree (#3587).

### API / data plane
- **Finding lifecycle** L1–L4: current-state merge, occurrence log, resolve
  reconcile, SDK ingest (#3470, #3480–#3483, #3465).
- **Hub read scale**: keyset pagination, deduped payloads, expression-indexed
  sorts, gzip/zstd compression (#3515–#3518, #3442, #3454).
- **Idempotent bulk ingest** and batch scan caps (#3462, #3474).
- **Hub observations partitioning** foundation with retention rollover (#3572).
- **Delta-stream connector** for SIEM/data-lake sinks (#3514).
- **OIDC JWT replay protection** via jti one-time store (#3561).

### UI / graph
- **Findings lifecycle** status in queue; estate roll-up navigation; blast-radius
  graph overlay; graph lens dock fix (#3551, #3507, #3502, #3505).
- **Labeled demo estate** surface lock states, including proxy, gateway, traces,
  and audit unavailable-state copy (#3467, #3468).

### CLI / headless
- **Findings push** CLI wired to hub current-state list (#3549).
- **Offline/air-gap** fixes for PyPI check, fleet push, and MCP version (#3556,
  #3557).

### Docs / positioning
- README product-first personas and FinOps lane; internal quick-wins queue moved
  to `docs/archive/` (#3580, #3587).
- Close post-audit hardening tracker **#3242** (corrective arc complete; forward work stays on epic issues).

## [0.92.0] - 2026-07-02

Release hardens the product path from first run to hosted POC: a user can
install or run the control plane, connect read-only sources, scan, triage in the
queue, inspect graph evidence, export compliance packs, and exercise runtime
controls without falling into stale docs or empty UI states.

### Hosted / first-run
- **Customer-zero hosted POC loop** with admin-key bootstrap, hosted preflight,
  smoke script, live brokered connector test actions, and invite-only POC docs.
- **Zero-config loopback serve** prints and wires a local development API key so
  `agent-bom serve` opens a working dashboard without unsafe global auth flags.
- **Product editions clarified** around local CLI/CI, self-hosted platform, and
  gated hosted POC; future managed SaaS plans are not presented as shipped
  capability.

### UI / operator workflow
- **Findings are now an issue queue** with evidence drawer, shared pagination,
  URL-synced filters, and server-side paging hooks so triage starts from a
  readable list instead of a dense wall.
- **Unified runtime surface** merges proxy and gateway views, adds a runtime
  live status strip for demos, and keeps fleet quarantine -> gateway deny as a
  one-click control loop.
- **Graph IA cleanup**: one Security Graph entry, discoverable graph lenses in
  navigation, full-canvas lens switching, older snapshot picker, attack-path
  queue paging, and WebGL renderer stability for large graphs.
- **Offline and empty-state polish** gives every major page actionable next
  steps when the API, data, or optional connector surface is unavailable.

### Cloud posture / CWPP / DSPM
- **Event-driven posture freshness** for AWS, Azure, and GCP: posture can be
  re-evaluated from provider events with polling/manual freshness surfaced in
  the Connections UI and docs.
- **Multi-cloud side-scan lifecycle** adds provider-neutral workload disk
  side-scan execution hooks, metadata-only workload findings, redacted secrets,
  target caps, guaranteed cleanup, and graph promotion of workload-disk
  resources.
- **DSPM classification enters graph risk** with opt-in S3 and GCS sampling,
  database sample classification, redacted evidence, and low-confidence
  sampling kept as evidence rather than risk inflation.

### Graph / scale / evidence model
- Governance, attack-path, and filtered graph payloads are capped so large
  estates stay responsive while retaining ranked evidence.
- Postgres scale evidence is checked in for release guidance, and large-graph
  UI tests now focus on stable render proof instead of brittle search drilldown.
- Exposure paths now flow through the unified `Finding` projection in
  Markdown, HTML, SARIF, and JSON outputs, reducing `BlastRadius` formatter
  drift.

### CLI / MCP
- Compact CLI output now has lane branding, a default posture card after scans,
  paged findings/remediation output, friendlier output-extension checks, and
  clearer idle compliance semantics.
- MCP startup is workflow-first: the server presents curated workflow prompts
  and demo scripts instead of making users start from the raw tool count.

### Docs / proof / reliability
- README, Snowflake connect docs, data-source docs, architecture diagrams, and
  product proof sections were refreshed for the current surfaces.
- CI reliability fixes cover graph E2E stability, access-review date flakes,
  autodiscovery timeouts, environment leakage between tests, and weekly
  dependency consolidation.

## [0.91.0] - 2026-06-30

A platform release: AI agents, MCP servers, and their tools become first-class
governed assets behind a runtime broker, while the SCA/SBOM/identity/cost depth
and the UI all level up. Availability, accuracy, security, and scalability are
treated as non-negotiable throughout.

### Runtime broker / gateway
- **OAuth 2.1 Authorization Server conformance** for the MCP auth spec — AS
  metadata (RFC 8414), dynamic client registration (RFC 7591), PKCE
  authorize/token endpoints, and JWKS — so standard MCP clients auto-authenticate
  to brokered MCP servers.
- **Inline agent-to-agent (A2A) mutual-auth enforcement** at the gateway relay
  (`off`/`warn`/`enforce`): rejects anonymous / unverified inter-agent and
  agent→MCP edges.
- **Per-tool-call OAuth scope mapping + DLP** on tool args/results: denies
  insufficient-scope calls and redacts/blocks sensitive data.

### SCA / reachability
- **Function-level reachability → CVE** — joins the Python symbol call-graph to
  advisory affected-symbols, marking findings `function_reachable` vs
  `package_reachable` for noise reduction.
- **`match_confidence_tier` surfaced across SARIF, JSON, and HTML** (not only the
  unified Finding), with canonical `cve_ids`.
- NVD capped-sync now ingests its unsynced tail across runs (no silent CVE
  drops); CPE inclusive/exclusive version bounds honored exactly; Go
  pseudo-version bounds; CycloneDX component de-duplication + finding-id scoping.

### SBOM / supply chain
- **Sign + attest generated SBOMs** (Ed25519 / HMAC, in-toto / SLSA) via
  `agent-bom attest`.
- **SPDX 2.2 / 2.3 emitter** + per-component checksums.

### Identity / FinOps
- **Owner-binding + attribution** on issued agent identities.
- **Reconcilable / actual cost rates** (vs static list price) with
  estimated-vs-reconciled provenance.

### Security hardening
- **SSRF blocked in the MCP repo-scan path** (egress validation, no
  redirect-follow, fail-closed remote bind) and the clone offloaded off the
  event loop.
- Server-authoritative tenant binding on audit ingest; pre-auth global IP rate
  limiter; X-Forwarded-For spoof fix; identity-keyed MCP rate limiter.
- Pickle scanner now scans oversized / disguised pickles (size-gate + memo
  evasion closed); `--fail-on-severity` fails closed on unknown/none.
- DB resilience: SQLite `busy_timeout` + WAL checkpoint; OSV archive streamed to
  disk (no OOM); KEV/NVD/GHSA wrong-shape + partial-sync guards.

### UI
- **Design-system foundation** — Collapsible, Card/Section, StatCard, shared
  entity icons, vendor logos, and consolidated state primitives.
- **Real connections experience** wired to the backend with vendor logos and
  honest provider readiness.
- Declutter + **capability-driven IA** ("Set up" badges, summary surfaces), a
  **data-driven AI-agent trust stack**, and interaction-state fixes (graph filter
  soft-lock, provider re-select, URL-as-source-of-truth filters).

### Output
- De-duplicated cloud CIS findings in SARIF and HTML; canonical OWASP-MCP/LLM
  codes from the tool-abuse rules.

## [0.90.0] - 2026-06-30

Native, self-sufficient SCA: distro-confirmed findings are benchmark-grade
(e.g. alpine 3.14.2), with an optional NVD CPE candidate
tier (review-grade, opt-in) for the long tail OSV and distro feeds do not cover —
on top of the multi-account CNAPP estate work below. No external-scanner
subprocess is required on the vulnerability path.

### Vulnerability scanning / SCA
- **Canonical CVE identity + match-confidence tiers.** `ALPINE-CVE-*` /
  `DEBIAN-CVE-*` are mapped to their canonical `CVE-*` for cross-tool parity, and
  every finding now carries a `match_confidence_tier`
  (`distro_confirmed` > `osv_range` > `osv_ecosystem` > `unfixed_distro` >
  `nvd_cpe_candidate`).
- **NVD incremental sync** (`NVD_API_KEY`) — pulls CVSS/CWE/CPE applicability
  into the local DB on an incremental, fail-closed checkpoint (the key travels in
  the `apiKey` header; a failed window is retried, never skipped).
- **NVD CPE candidate matching** — a new `cpe_matches` table + matcher map
  components to `cpe:2.3` applicability ranges to flag non-ecosystem / OS /
  vendor software OSV and distro feeds miss, with vendor disambiguation for
  false-positive control. Opt-in via `AGENT_BOM_ENABLE_CPE_MATCH`, surfaced as
  the review-grade `nvd_cpe_candidate` tier (long-tail only, off by default).
- **Parallel OSV batches** with bounded concurrency
  (`AGENT_BOM_SCANNER_OSV_BATCH_CONCURRENCY`, default 3) and a pipeline-wide 429
  backoff so large inventories finish faster without hammering OSV.
- **Forced OSV fallback for sparse/EOL distro releases** so end-of-life images do
  not silently miss advisories.
- **Real offline + online scan-accuracy validation** — a deterministic offline
  three-tier (OSV / distro / CPE) regression net plus live OSV ground-truth and an
  external-scanner binary-diff harness.

Deepens the cloud/CNAPP estate from a single-provider inventory into a
multi-account, multi-region, tenant-scale model that rolls up readably in the
graph, adds agentless workload (CWPP), audit-trail behavioral, and ASPM
application views, and lands a read-only-by-default connect path on every cloud.
All cloud access stays read-only and in-account: nothing leaves the customer's
account.

### Cloud / CNAPP
- **Estate inventory deepened across all three clouds**, with every asset wired
  into the unified graph: AWS (RDS, DynamoDB, Lambda, EKS, ELB, VPC, KMS,
  Secrets Manager, CloudFront, ECR, Redshift, SNS/SQS) with multi-region
  aggregation; Azure (Key Vault, Container Registry, SQL/PostgreSQL/MySQL, AKS,
  network topology, messaging/cache/disks/App Service, and edge/WAF — App
  Gateway, Front Door, API Management); GCP (GKE, Cloud Run, Functions, Cloud
  SQL, VPC, disks, Pub/Sub).
- **Tenant-scale account hierarchy as a navigable `CONTAINS` backbone:** AWS
  Organizations (org / OUs / accounts / SCPs), Azure management-group tree with
  multi-subscription fan-out, GCP Org → Folders → Projects fan-out, and a
  Snowflake organization → accounts roll-up.
- **Normalized cross-cloud resource model** so AWS, Azure, and GCP assets share
  one schema and ingest into the graph identically.
- **Read-only audit-trail ingestion.** CloudTrail, Azure Activity Log, and GCP
  Cloud Audit Logs are read via read-only APIs and reduced to behavioral
  `ACCESSED` / `INVOKED` graph edges (principal → resource, counts and
  last-seen only — raw events never persist). Opt-in via
  `AGENT_BOM_AUDIT_TRAIL`.
- **Agentless AWS EBS disk side-scan (CWPP).** Snapshots a volume, attaches it
  to an in-account collector, and reads package/filesystem metadata. Temp
  snapshots and volumes are cleaned up in a guaranteed `try/finally`, with an
  orphan sweep recovering after a hard crash; no block data leaves the account.
- **Registry-wide container image sweep** across ECR, ACR, and GAR: enumerates
  repositories and tags via read-only APIs, deduplicates by image digest, scans
  freshest first, and caps work at `AGENT_BOM_REGISTRY_MAX_IMAGES`.
- **Effective-permission foundation:** AWS IAM inline-policy enumeration (not
  just attached managed policies), Azure RBAC role-assignment inventory with
  `HAS_PERMISSION` edges, and GCP instance internet-exposure plus IAM privilege
  classification.
- **Cloud data sensitivity classified from resource tags/labels** across AWS,
  Azure, and GCP.
- **Snowflake estate depth:** identity/auth-posture graph with login-anomaly
  detection (impossible travel, failed-login bursts) and MITRE tagging, object
  and dependency-lineage graph, exfil graph (shares, external stages, sensitive
  objects), data-pipeline objects (tasks/streams/pipes), integrations, iceberg
  and external tables, and governance/activity discovery wired into the scan.
- **CIS posture converges into the findings stream and the gate.** Cloud CIS
  failures now flow into the unified findings stream and the severity gate,
  drive the verbose posture headline, and render as a grouped, readable report
  in the terminal and HTML at estate scale.
- **Unified cloud-aware scan runs across every configured provider in one
  command.** Providers are detected by credential source rather than a CLI on
  `PATH`, native GCP service-account impersonation and Azure subscription
  auto-derivation give keyless read-only connection, and inventory tolerates
  partial permissions instead of failing when a role lacks a single grant.

### Graph
- **Estate-scale `CONTAINS` roll-up with drill-down.** A 1000+ node estate
  collapses along its containment tree to a handful of top-level container
  nodes, each carrying aggregate descendant counts, a by-type breakdown,
  worst-severity, a per-severity histogram, and internet-exposed /
  toxic-combination flags propagated from descendants; an attack-path-first
  view and one-level drill-down are exposed at `GET /v1/graph/rollup`.
- **ASPM correlation layer.** AppSec findings (SCA, secrets, IaC, container,
  SBOM, AI-BOM) are organized around `APPLICATION` nodes via `BELONGS_TO`
  edges, deduplicated across sources, with per-application risk rolled up.
- **Toxic-combination evaluator emits enforceable findings** rather than only
  annotating the graph.
- **New cloud graph edges:** normalized cloud resources ingested as nodes, an
  internet-exposure edge (public IP → load balancer), and a VM →
  managed-identity privilege edge (`ASSUMES`).

### Cost / FinOps
- **LLM spend fused into the unified graph.** Per-node `cost_usd` /
  `cost_usd_30d` attributes roll up along `CONTAINS` edges into
  `subtree_cost_usd`, and nodes that are both high-spend and high-risk are
  flagged `cost_risk_priority` for cost × exposure triage.

### Identity / NHI
- **Lifecycle enforcement for agent identities** with JIT (time-bound) grants.

### Gateway / Runtime
- **Policy engine hardened** with fail-closed evaluation, quarantine,
  conditional access, a plugin surface, and OCSF webhook interop.
- **Runtime-observed incidents feed back into the unified graph**, and the
  gateway consumes graph reachability for pre-emptive blocking.
- **Hardened outbound delivery foundation** with OTLP trace emission.

### Remediation
- **Advisory remediation foundation with least-privilege-to-apply.** Each fix
  carries the concrete, minimal IAM actions the operator's own apply role would
  need, plus optional text-only runbook/Terraform artifacts. Strictly advisory:
  `applied` and `auto_remediation` are always false — agent-bom recommends,
  the operator applies.

### AI / MCP security
- **Adversarial red-team series:** LLM-harnessed adversarial variant
  generation, bias/toxicity/hallucination detectors, and an adversarial-coverage
  governance score with live-target firing.
- **Obfuscation-resistant prompt-injection detection** (raises detection on
  obfuscated payloads from 24% to 100% on the bundled corpus).
- **Credentials ranked by exposure even without a CVE**, and
  **hardware/firmware attestation evidence ingest**.
- **Deterministic tool/skills surfaces** so agent-side caching stays stable.

### Scanner
- **Incomplete-coverage warnings for end-of-life OS releases.** After distro
  detection, image/filesystem scans flag any `ecosystem:release` (e.g.
  `debian:10`, `ubuntu:18.04`, `alpine:v3.x`) that has many OS packages present
  but (near-)zero advisory rows in the local DB while the data source clearly
  carries the same distro family at other releases — the signature of an EOL
  release the feed has dropped. The warning surfaces on the console (a red
  panel), in the JSON report (`coverage_warnings`, mirrored under
  `summary.coverage_warnings`), and in the scan-warning count, so a low or zero
  count for an uncovered release is never read as a clean bill of health. The
  check is threshold-based and data-source-agnostic; it does not change matching
  or suppression.

### CLI
- **Canonical front-door verbs** (`connect` / `scan` / `graph` / `report` /
  `up`) as the primary entry path.
- **Capability doctor** surfaces every gated feature, its current state, and
  the unlock path.
- **`scan` accepts an optional positional `PATH`**, and scans can be grouped
  into parent-child batches.
- **`agent-bom image` / `agent-bom fs` gained `--ignore FILE`** to suppress
  named advisories (CVE / GHSA / OSV) from both the report and the
  `--fail-on-severity` gate. `FILE` may be a flat newline-delimited id list
  (`#` comments allowed, e.g. `.image-scan-ignore`) or a structured
  `.agent-bom-ignore.yaml`. ID matching is alias-aware (a GHSA id suppresses its
  aliased CVE and vice versa).
- **`--exclude-unfixable` now applies to the report and gate**, not just SARIF:
  findings with no available fix are dropped from console/JSON output and from
  the `--fail-on-severity` gate (an "ignore unfixed" policy).

### CI / Tooling
- **Image and filesystem vulnerability gates are self-hosted on agent-bom**
  (dogfooding). The CI/release/container-rescan/refresh workflows now run
  `agent-bom image` / `agent-bom fs` (OS-layer dpkg/rpm/apk + application
  dependencies) and `agent-bom secrets` in place of the previous third-party
  image/filesystem scanner; no workflow depends on an external scanner.

### API
- **REST cloud-scanning endpoints** with MCP write-tool role enforcement.
- **Multi-cloud connection brokers.** A stored read-only cloud connection now
  launches a read-only scan for every provider — AWS (`sts:AssumeRole` with the
  decrypted ExternalId), Azure (`ClientSecretCredential`, Reader role), GCP
  (service-account credentials scoped to `cloud-platform.read-only`), and
  Snowflake (key-pair connection). Provider-specific non-secret parameters are
  stored in a new `auth_params` column (the single reversible secret stays in the
  encrypted `external_id`); the secret is decrypted only at broker time and never
  logged or returned. The background scan scheduler covers all four providers.
- **Shared backend contract and selection factory** for control-plane stores.

### Deploy / Packaging
- **One-apply EKS platform module** (`deploy/terraform/platform-eks/`) plus a
  three-tier deploy-anywhere guide ([`docs/DEPLOY_PLATFORM.md`](docs/DEPLOY_PLATFORM.md)).
- **Connect-a-cloud Terraform modules** provision one read-only role per cloud
  (AWS `SecurityAudit`, Azure `Reader`, GCP `roles/viewer` +
  `iam.securityReviewer`), with keyless federated-credential options and no
  long-lived keys; CI enforces that the connect modules stay read-only.
- **Keyless read-only collectors for EKS / GKE / AKS** via workload identity
  (IRSA / Azure workload identity / GCP Workload Identity Federation).
- **CloudFormation one-click read-only AWS scan** via CodeBuild.

### UI
- **Cross-domain overview landing page** and **cloud CIS benchmark drill-down**
  on the compliance dashboard.

### Changed
- **`agents --agent-mode` summarizes the scan payload by default.** The envelope
  now emits `data_mode: "summary"` with a bounded `data` field — counts
  (packages by ecosystem, findings/exposure by severity), the top 10 ranked
  findings and exposure paths, and a summary-level agent inventory — instead of
  inlining the full per-package provenance dump. For a ~877-package repo the
  stdout envelope drops from ~27 MB to a few KB so it fits an LLM/automation
  context window. Pass `--agent-mode-full` (`data_mode: "full"`) or write JSON to
  disk with `-o report.json --format json` for the complete report;
  `data.full_report` records how to obtain it.
- **Vulnerability cache auto-refreshes** and surfaces a freshness indicator.
- Flat (non-graph) outputs prefer canonical findings for consistency with the
  graph view.
- **Demo-mode offline scans resolve a curated bundled advisory set, not the full
  local DB.** In demo mode an offline scan reports against the bundled demo
  advisory DB (deterministic, every demo package maps to at least one advisory),
  which surfaces fewer, curated findings than a real offline scan against the
  full local vulnerability DB. The active source is labeled in scan output
  (`bundled demo advisory DB` vs `local vulnerability DB`). Demo screenshots and
  finding counts therefore differ from real-scan numbers by design — compare
  like-for-like (real scans use the local/synced DB).

### Fixed
- **Fixed agent-mode summary counts.** The envelope `summary.packages` field
  previously fell through to the full package list; it now reports an integer
  count.
- **Offline coverage gaps now warn instead of discarding real findings** (was a
  silent false-negative).
- **Go `go.mod` block-`require` parsing** no longer emits a phantom package, and
  **Cargo manifests parse without a lockfile** including target and workspace
  dependencies.
- **Hardcoded-secret findings surface in JSON and SARIF**, not only the console,
  and **SARIF locates dependency findings at their own ecosystem's manifest**.
- **MCP `check` tool** parses pip specifiers and flags errors, reads
  nonexistent explicit versions as not-clean, and raises a clean error (instead
  of crashing) on an out-of-sandbox scan path.
- **Legacy context graph reads `credential_env_vars`** so lateral-movement
  analysis is no longer credential-blind, and the **CLI graph export includes
  the cloud estate** (was local-only).
- **Subscription-scoped cloud misconfigurations anchor to their account node**
  in the graph.
- **CLI degrades gracefully on low disk** instead of crashing, and the **cloud
  inventory summary counts every asset collection**.
- **SQLite/Postgres timestamp alignment, dedup, and cost-table DDL** reconciled
  across the two store backends.
- Request models reject unknown fields (`extra=forbid`), and cloud API routes
  resolve CodeQL info-exposure and log-injection findings.

---

## [0.89.2] - 2026-06-22

Patch release. Supersedes 0.89.1, which was tagged but never published: a second
release-workflow startup failure (distinct from the 0.89.0 cause). Same feature
set as 0.89.0.

### Fixed
- **Release workflow startup failure (reusable-workflow permissions).** The
  `deploy-mcp-sse` job called a reusable workflow without declaring job-level
  `permissions`, so it inherited the top-level deny-all default while the called
  workflow requested `contents: read`. A reusable workflow cannot request more
  than its caller grants, so GitHub aborted the entire release run at startup.
  The job now declares `permissions: contents: read`, matching the pattern the
  `docs-site` reusable call already uses.

---

## [0.89.1] - 2026-06-22

Patch release. Supersedes 0.89.0, which was tagged but never published: a release
workflow defect aborted the run at startup before any artifacts were built.

### Fixed
- **Release workflow startup failure.** The `self-scan-gate` job referenced a
  `needs.version-guard` output without declaring `version-guard` in its `needs`,
  which GitHub rejects at workflow startup — failing the entire release run with
  no jobs created. The job now declares both dependencies. No product code
  changed from 0.89.0; this release carries the identical feature set documented
  below.

---

## [0.89.0] - 2026-06-22

This release extends agent-bom from AI/MCP supply-chain scanning into estate-wide
cloud, non-human-identity, and FinOps governance, all converging into the unified
security graph. New value is reachable from every surface: CLI, MCP tools, REST
API, SDKs, and the dashboard.

### Cloud / CNAPP
- **Estate-wide cloud asset inventory.** New AWS, Azure, and GCP inventory
  scanners enumerate the cloud estate and wire discovered assets into the unified
  security graph, so cloud resources participate in attack-path and exposure
  analysis instead of being scanned in isolation.
- **Network placement for reachability.** Cloud assets now capture network
  placement metadata (subnet/exposure context) that feeds reachability analysis.
- **Regulatory-regime data classification.** Data stores are classified by
  regulatory regime rather than a binary sensitive/not-sensitive flag, giving
  exposure paths jurisdiction-aware severity.
- **Crown-jewel and toxic-combination attack paths.** The graph derives
  crown-jewel exposure and toxic-combination paths, plus pure broad-scope-identity
  paths, surfaced as first-class attack paths.
- **Dormant cloud-inventory, NHI-discovery, cost-center, and credential-expiry
  scan paths are now wired into the scan pipeline** instead of remaining inert.

### Identity / NHI
- **Non-human identity discovery.** agent-bom discovers non-human identities from
  Okta and Microsoft Entra into the graph, with discovery endpoints and graph
  wiring.
- **NHI usage right-sizing and risk scoring.** Per-identity dormancy/orphan
  detection, usage right-sizing recommendations, and a per-identity risk score.
- **Access-review / recertification campaigns.** NHI access-review and
  recertification campaign workflows for periodic attestation.
- **Credential expiry and rotation governance** across the API and auth layers,
  surfacing soon-to-expire and unrotated credentials.

### Cost / FinOps
- **Cluster-safe Postgres cost store** for multi-replica budget enforcement, so
  budgets hold across a horizontally scaled control plane.
- **LLM spend burn-rate forecasting** with budget-runway projection.
- **Cost chargeback / allocation tags** and seasonal anomaly baselines for
  per-team and per-workload cost attribution.

### Gateway / Runtime
- **Unified Gateway Live Feed** consolidating tool-call authorization, DLP, and
  LLM-call visibility into a single real-time stream.
- **Firewall enforcement in the relay** with secure-by-default caller
  authentication.
- **Detection-to-enforcement actions:** quarantined fleet agents are isolated,
  behavioral-drift incidents and cost-spike anomalies are acted on (not just
  reported), with policy block reasons redacted in caller-facing responses.
- **Break-glass attempts are always audited** and the proxy locks in a
  fail-closed sandbox posture.

### Supply-chain
- **Malicious model-pickle detection** via safe opcode disassembly, flagging
  dangerous pickle opcodes without executing the artifact.
- **Opt-in entropy detection** for novel/unknown secrets beyond fixed patterns.
- **Corrected npm caret/tilde semver bounds** for `0.x` ranges in transitive
  resolution.
- **Data-quality confidence** is now computed on native findings.

### AI / MCP security
- **Agent->MCP and agent-to-agent (A2A) auth-posture scanning**, including a
  dedicated governance MCP server.
- **New governance and cost capabilities exposed as MCP tools** with surface-count
  freshness locking, plus unified-Finding suppression / AI-context / reachability
  fields surfaced in JSON, SARIF, and OCSF output.
- **Scan a public repository by URL** (`scan --repo`, `repo_url` MCP argument).

### Infra / DX
- **Distributed scan execution** via a Postgres dispatch queue for horizontal
  scale, and **hardened enterprise tenant boundaries** across the control plane.
- **New CLI commands for cost and identity governance** so operators reach the new
  value without the API.
- **Cost-forecast / chargeback and NHI-governance console panels** in the
  dashboard, with governance lineage colors mapped in the graph.
- **Committed OpenAPI contract and codegen-parity Go/Python/TypeScript SDK
  clients**, with route parity derived from the OpenAPI schema for FastAPI
  forward-compatibility.
- **Multi-hop attack-path fusion** and a graph **evaluation harness** for
  regression-testing derived paths.
- CI test runs are parallelized with pytest-xdist (~12min to ~5min), and Docker
  builds use a stable Python runtime.

### Security
- **Token-only auth for ClickHouse and ServiceNow integrations** with email PII
  masking.
- SCIM posture and misconfiguration messages are sanitized so internal exception
  detail is not disclosed in the posture surface.
- API idempotency keys are bound to their request payloads to prevent cross-payload
  replay.

### Docs
- README, Docker Hub, and PyPI descriptions aligned with current capabilities.
- New repo map, clean architecture data-flow diagrams (dark/light), and a
  start-here guide; root `glama.json` added with improved MCP tool descriptions.

---

## [0.88.6] - 2026-06-05

### Added
- **Agent governance parity controls.** Budget enforcement, signed identity lifecycle audit events, per-tool scopes, JIT/time-bound access, conditional access decisions, and identity/cost/drift UI cockpits are now wired through the control plane, API, MCP tools, tests, and dashboard surfaces.
- **CNAPP-style security graph depth.** Exposure paths now include cloud exposure, sensitive data paths, effective-permission escalation, governance decisions, action-level IAM privilege, port-aware network exposure, runtime-observed reachability, and policy/webhook evidence with distinct node and edge semantics.
- **Guarded remediation flow.** Remediation can now stage guarded apply operations and draft pull requests with explicit policy, scope, and audit evidence before changes are applied.

### Changed
- README and product screenshots now emphasize scan-to-runtime evidence, graph-backed findings, environment/identity/IAM attack paths, readable legends, and contained dashboard visuals.
- Dependency automation was consolidated across Python, UI, and GitHub Actions updates so approved dependency PRs land as coherent review units.
- The Docker latest refresh workflow now handles API and UI image refresh paths together after a release tag is published.

### Fixed
- Upgraded `aiohttp` to address the GitHub security alerts for cross-origin redirects with per-request cookies and unsafe deserialization.
- Reworked Railway SSE deployment to run from the trusted release workflow tag instead of checking out `workflow_run` metadata in a privileged deployment context, and refreshed the legacy `agent-bom-scheduled` SARIF category from the current self-scan workflow.
- Hardened the UI runtime Docker image by removing build-time package-manager tooling from the final image, clearing the Trivy gate that blocked `agentbom/agent-bom-ui:latest` refresh.
- Tightened dashboard and README visual containment so graph labels, path headers, cards, and code samples wrap inside their containers across dark, light, and mobile views.

---

## [0.88.5] - 2026-06-01

### Added
- **Runtime cost attribution (FinOps).** Token counts on ingested OpenTelemetry GenAI spans are priced via an open, operator-tunable cost model (`AGENT_BOM_COST_MODEL_JSON` overrides), persisted per tenant, and exposed as per-agent/model/provider spend with budgets at `GET /v1/observability/costs` and `GET`/`PUT /v1/observability/costs/budget`. New `cost_report` MCP tool. See `docs/COST_MODEL.md`. Metadata only — no prompts or responses are read.
- **Agent identity lifecycle.** agent-bom can now issue time-scoped agent identities (`abi_` tokens, stored only as SHA-256 hashes), rotate them with an overlap window, and revoke them: `POST /v1/identities`, `POST /v1/identities/{id}/rotate`, `POST /v1/identities/{id}/revoke`, plus list/detail. The proxy and gateway resolve issued tokens and fail closed on revoked/expired identities.
- **Blueprint-drift incidents.** Drift evaluations that report `drift_detected` now persist a durable, deduplicated, tenant-scoped incident, listable at `GET /v1/runtime/drift/incidents` and resolvable at `POST /v1/runtime/drift/incidents/{id}/resolve`. New `drift_incidents` MCP tool. Blueprints become enforced contracts with an audit trail rather than advisory reports.
- `agent-bom quickstart --run` executes first-run onboarding end to end: writes the bundled sample stack, runs a graph-persisting scan that populates the local security-graph cockpit, and seeds the secure-by-default gateway baseline policy. The print-only guide remains the default.

### Changed
- The multi-MCP gateway relay now enforces control-plane `GatewayPolicy` bindings (`bound_agents`/`bound_agent_types`/`bound_environments`) scoped to the resolved source agent — matching the per-MCP proxy — via a new `gateway serve --policy-bundle` flag. Previously these bindings were enforced only by the proxy.

### Fixed
- `agent-bom iac <file>` now scans a single named file instead of silently returning zero findings (previously only directories were scanned).
- Fresh Postgres deployments include the `graph_edges` edge-versioning columns in the `init.sql` baseline and a self-contained Alembic migration, fixing `column "valid_from" does not exist` on migration-only/read-only paths.
- The multi-replica tenant-quota guard fails closed (HTTP 503) when its Postgres advisory lock is unavailable under a clustered control plane, instead of silently degrading and overshooting the quota.
- Removed committed macOS Finder duplicate files and hardened the duplicate-artifact guard to catch untracked copies in the working tree.

---

## [0.88.4] - 2026-05-26

### Added
- Control-plane evaluation runs with dataset-version linkage, score summaries,
  trace metadata, and SDK helpers for Python, Go, and TypeScript clients.
- TypeScript control-plane client coverage for findings, graph exposure paths,
  governance decisions, datasets, intel, runtime, and evaluation workflows.
- Scope-catalog discovery for auth operators and clearer empty-state messages
  for graph exposure-path queries.

### Changed
- Scan context graph responses now expose the unified graph envelope while
  preserving the legacy context-graph fields for existing consumers.
- Prompt scan results now emit normalized top-level findings with prompt-scan
  provenance and evidence links instead of remaining only in prompt-specific
  report data.
- MCP registry sync now prefers the official MCP registry API and records
  defensible source provenance before falling back to legacy sources.

### Fixed
- Tenant context handling now requires middleware-populated tenant state instead
  of route-level default fallbacks, and Postgres RLS bypass events are chained
  into audit evidence.
- First-run Docker Compose profiles now render with the documented example
  environment file, and release docs clarify cloud posture versus IaC scan lanes.
- Weekly dependency and GitHub Actions updates keep the release automation,
  Docker login, Docker Buildx, CodeQL, and lockfile surfaces current.

---

## [0.88.3] - 2026-05-24

### Added
- Go control-plane SDK, Python SDK ergonomics for positional client payloads,
  route-parity checks, and richer SDK examples for headless integrations.
- Governed threat-intel daily brief inputs, vendor advisory source metadata,
  package/advisory matching, and documented source boundaries.
- Plugin registry status inspection through CLI and API without loading
  third-party plugin code.
- GitHub Action posture outputs and per-finding annotations for downstream CI
  gates and pull-request review workflows.
- SCIM bulk lifecycle endpoint, database evidence fallback lanes, firmware CPE
  candidate enrichment, persistent issue mappings, and code-topology graph
  schema types.
- Offline HTML export mode that omits external JavaScript assets while keeping
  static report evidence available.

### Changed
- Product and security docs now align around the self-hosted, read-only,
  pluggable, interoperable trust contract and scoped outbound boundaries.
- Shared scan option contracts now prepare the CLI for API/control-plane
  delegation without changing existing command behavior.

### Fixed
- Proxy WebSocket auth now uses the same key store, OIDC, tenant, trusted-proxy,
  and RBAC enforcement as the REST surface.
- Production audit HMAC now requires a persistent key unless ephemeral local
  mode is explicitly enabled; skills scan and rescan events are chained into
  the audit log.
- Shield write actions now require both admin role and explicit write scope
  across API and MCP tool paths.
- Snowflake tables now define tenant row-access policies, and modern OIDC
  signing algorithms are accepted.
- CSP relaxation is scoped to API docs assets, and dashboard CSP manifests are
  guarded.
- Scan executor lifecycle shutdown is coordinated, graph delta alert scans are
  optimized, direct MCP package specs scan correctly, and fleet agent list
  aliases avoid misleading 404s.
- Auth rejection, tenant isolation, SDK payload, SCIM bulk, plugin registry,
  and release-consistency regressions now have targeted coverage.

---

## [0.88.1] - 2026-05-22

### Fixed
- Refreshed the bundled MCP registry catalog before release so registry
  lookup, marketplace checks, and the release freshness gate use the current
  server catalog metadata.

---

## [0.88.0] - 2026-05-21

### Added
- Python control-plane client with typed helpers for health, findings, bulk
  ingest, graph schema, runtime production index, Agent BOM manifest, threat
  intel sources, advisory lookup, and package matching.
- Plugin entry-point registries for `agent_bom.mcp_tools`,
  `agent_bom.advisory_sources`, and `agent_bom.runtime_emitters`, plus
  documentation for third-party extension authors.
- Runtime blueprints now include a drift evaluation endpoint and MCP tool so
  operators and agents can compare live runtime posture with an approved role
  profile without exposing raw prompts, arguments, responses, or credentials.
- MCP server mode now exposes read-only runtime posture tools for production
  index summaries, runtime blueprints, proxy/gateway status, Shield session
  status, and inter-agent firewall decision dry-runs.
- Runtime audit read tools now expose audit query, audit integrity, and proxy
  alert summaries through MCP for agent-native investigations.
- Agentic identity graph edges and runtime identity projections now flow into
  canonical graph exports and API/UI graph surfaces.
- AI visibility manifest signals and dashboard filters now summarize agent,
  MCP server, tool, owner, risk, freshness, and runtime posture.

### Fixed
- Gateway and proxy rate limiting now scope buckets by source agent where
  identity is available, with tenant-local anonymous fallback and explicit
  metric labeling.
- Scanner accuracy now catches additional Dockerfile risk patterns, training
  metadata PII, prompt-injection sentinels, and image `--output` JSON file
  writes.
- Graph exports now bound large Mermaid and SVG output by default, preserve
  full graph counts, include omitted-node summaries, and support full output
  opt-in.
- Agent inventory validation now mirrors the full discovery profile catalog and
  returns clearer did-you-mean errors for common schema mistakes.
- SARIF output now exposes the compliance taxonomy catalog for consumers that
  read `tool.extensions`, while retaining per-finding taxa.
- Product metrics now count the root dashboard page and refreshed MCP tool
  counts across generated metrics, MCP docs, Docker MCP metadata, and release
  consistency checks.
- Runtime detector documentation and TypeScript SDK detector counts are aligned
  with the exported runtime package.

### Changed
- README, Docker Hub, data-model, deployment, enterprise, and runtime security
  docs now reflect the v0.88 control-plane story: Python SDK, plugin slots,
  runtime posture, graph readability, identity projections, and first-run proof.
- First-run samples now use intentionally vulnerable package versions that
  produce real findings, with regression coverage for the expected signal.
- The data-model atlas is generated from code and live schema sources so graph
  entity and relationship counts stay aligned with API/UI/runtime surfaces.

---

## [0.87.1] - 2026-05-18

### Added
- Agent BOM manifest now has a canonical local/tenant inventory contract with
  a top-level `agent-bom manifest` CLI command, `GET /v1/agent-bom/manifest`,
  redacted credential references, graph relationships, and a dashboard cockpit
  for agent/MCP/tool visibility.
- Architecture docs now include an AI governance control-plane diagram that
  ties scans, fleet and endpoint inventory, runtime decisions, threat intel,
  Agent BOM manifests, graph evidence, and human/agent surfaces together.
- **Runtime production index** - added a tenant-scoped
  `/v1/runtime/production-index` security-observability endpoint for
  proxy/gateway traffic with tool-call volume, policy decision summaries,
  active runtime sources, freshness, and explicit retention posture without
  exposing raw prompts, arguments, responses, or credential values.
- Threat-intel lookup and matching surfaces now expose local source freshness,
  advisory lookup, and package/purl inventory matching over REST and MCP, with
  canonical CVE/GHSA/OSV/CWE IDs plus evidence links.

### Fixed
- Scorecard vulnerability and token-permission hygiene now avoids counting
  committed parser fixtures as live dependency exposure and scopes selected
  workflow write tokens to the jobs that require them.
- Graph schema now exposes static `node_types` and `edge_types` aliases from
  the canonical enum taxonomy, so empty graph stores still return the complete
  type catalog for clients.

### Changed
- Root README now serves as a shorter public front door focused on first run,
  shipped surfaces, deployment links, trust boundaries, and docs handoffs
  instead of duplicating long deployment and integration reference sections.
- **Multi-agent operating contract** - promoted shared engineering, PR style,
  and release-readiness rules into `.agents/AGENTS.md` so any agent following
  the [agents.md](https://agents.md) convention (Claude, Codex, Cursor,
  Continue, Aider, Windsurf) reads the same contract. Added a thin Claude-only
  `CLAUDE.md` addendum for memory and tool semantics.
- **Public documentation positioning** - external scanner ingest is now
  described by standard format (CycloneDX, SPDX, SARIF, scanner-native JSON)
  instead of by vendor name across site-docs, examples, ADRs, MCP server
  metadata, and the boundaries documentation.

---

## [0.87.0] - 2026-05-17

### Added
- **Graph investigation product lane** - shipped bitemporal graph edges,
  measured benchmark evidence, hardened large-graph overview fallback,
  API-native `ExposurePath`, toxic-combo graph projection, semantic clusters,
  renderer-switch contracts, Sigma WebGL overview, light-mode graph token
  fixes, and optional Neptune backend plumbing (#2541, #2542, #2543, #2544,
  #2553, #2554, #2555, #2556, #2558, #2562, #2564, #2568).
- **Identity-aware investigation flows** - added identity graph taxonomy,
  AWS IAM enrichment, ExposurePath-first dashboard brief, ExposurePath output
  parity across JSON/SARIF/Markdown/HTML, and agent-native REST/MCP graph
  tools for exposure paths and deploy decisions (#2565, #2566, #2567, #2572,
  #2573, #2574, #2577, #2604).
- **Headless control-plane primitives** - added the TypeScript control-plane
  client, public Python SDK entry points, versioned inventory ingestion,
  normalized bulk findings ingest, dataset version registry, posture webhook
  outbox and status API, posture streaming contract docs, and local
  entitlement metadata hooks (#2601, #2602, #2603, #2606, #2607, #2609,
  #2611, #2613, #2614).
- **IaC and data-stack scanning** - added first-class dbt project security
  scanning for project metadata, profiles, packages, SQL models/macros, seed
  files, and dbt CI workflow guardrails (#2615).
- **Skills scanner hardening** - decoupled content and provenance verdicts,
  routed medium behavioral findings to review, added policy-aware CI gates,
  improved scanner evidence accuracy, and emitted SARIF for skill findings
  (#2569, #2570, #2575, #2590, #2591, #2592).
- **Release proof and positioning** - refreshed product metrics, release proof
  screenshots, graph release positioning, agent-first product boundaries,
  product lane boundaries, and the docs/runtime posture-event contract without
  claiming unshipped Kafka, Kinesis, Pub/Sub, Event Hub, or EventBridge
  adapters (#2530, #2560, #2563, #2579, #2580, #2588, #2600, #2602, #2605).
- **Dependency and release automation updates** - refreshed UI and SDK
  development dependencies, Python Alpine base image, Docker base-image policy,
  PyPI native attestations, and Windows endpoint runner pinning (#2520, #2534,
  #2535, #2536, #2537, #2538, #2539, #2581, #2582, #2583, #2584, #2585).

### Fixed
- **SQLite graph upgrade blocker** - fixed legacy local graph DB read-path
  migrations so existing `graph.db` files add time-versioned edge columns
  before `/v1/graph*` endpoints query them (#2561).
- **Audit chain and runtime integrity** - reconciled runtime AES-CMAC audit
  verification with the control-plane HMAC audit table and removed raw
  exception leakage from audit-integrity errors (#2516, #2571).
- **CLI and output contract gaps** - made `cryptography` a core dependency for
  `agent-bom audit`, honored `-o/--output` from wrapper scan commands when CLI
  profiles are active, preserved auditor enrichment metadata across non-JSON
  exports, and kept `agent-bom check --agent-mode` machine-readable (#2524,
  #2525, #2526, #2527, #2540).
- **Scanner/runtime data quality** - threaded offline mode into enriched scans,
  tightened CLI runtime audit gates, aligned canonical IDs across report and
  graph surfaces, fixed API gateway data audit gaps, and cached agent discovery
  responses for the API/UI path (#2517, #2518, #2519, #2521, #2522, #2523,
  #2557).
- **Postgres scale evidence workflow** - restored the scheduled Postgres scale
  evidence workflow environment contract and kept test-only Postgres settings
  from leaking into unrelated scheduler and Snowflake startup paths (#2616).

---

## [0.86.5] - 2026-05-11

Release-gate patch for the `v0.86.4` train. This release keeps the same
product scope and updates the locked `urllib3` dependency to clear the
shipping dependency audit before publishing signed artifacts.

### Fixed
- **Release dependency audit** - `urllib3` is locked to `2.7.0`, clearing the
  high-severity findings that blocked the release self-scan gate.

---

## [0.86.4] - 2026-05-11

Patch release for the post-`v0.86.3` release train. This release tightens the
CLI contract for automation, refreshes graph/dashboard release evidence,
hardens CI retrigger behavior, and closes the final pre-release identity and
fixture gaps before tagging.

### Added
- **Agent-mode CLI output contract** - `--agent-mode` now gives automation a
  stable output envelope with bounded confidence fields, token-budget handling,
  and deterministic error structure (#2479).
- **Reusable scan progress streaming hook** - the dashboard can consume the
  existing scan stream path through shared UI plumbing instead of one-off page
  code (#2477).

### Fixed
- **Release output contracts** - output paths now align with the requested
  format, stdout behavior is explicit, and JSON output exposes the release
  posture grade consistently (#2474).
- **Native Debian severity fallback** - native image scans derive missing
  Debian severity data from related canonical CVE records where available
  (#2473).
- **Audit and API guardrails** - audit integrity now fails closed without a
  configured HMAC key, API rate limits use release-ready defaults, pagination
  bounds are explicit, and agent identity enforcement requires verifiable JWT
  policy instead of accepting unsigned identity claims (#2470, #2480).
- **Graph and dashboard release polish** - graph labels, defaults, evidence
  export controls, blast-radius panels, and release screenshot contracts were
  aligned with the shipped graph surfaces (#2469, #2472, #2475).

### CI
- **PR retrigger automation** - ready-PR refresh now avoids the frozen-check
  loop by using a dedicated automation token path and not disturbing active
  runs (#2478).

---

## [0.86.3] - 2026-05-08

Patch release for the OpenSSF Scorecard regression and post-`v0.86.2` release
readiness fixes. This release keeps the public security posture evidence aligned
with the live `main` branch after the scorecard, CI/runtime toolchain, scanner
registry, graph serialization, demo remediation, and dependency-refresh work.

### Added
- **Scanner driver registry** - scanner driver metadata is now centralized so
  CLI/API/docs surfaces can reason about scanner capabilities without drifting
  across hand-maintained lists (#2337).

### Fixed
- **OpenSSF Scorecard regression** - tightened scorecard workflow permissions
  and README positioning so the badge and scorecard run stay aligned with the
  least-privilege release posture (#2359).
- **CI runtime toolchains** - aligned runtime/toolchain setup after main CI
  failures, including Alpine build prerequisites for native dependencies
  (#2339, #2348).
- **Signed PR refresh automation** - hardened the ready-PR refresh path used to
  recover approved branches without weakening signed-commit expectations
  (#2338).
- **Demo remediation trust** - tightened demo remediation output so first-run
  evidence remains reproducible and does not overstate unverified fixes (#2351).
- **Self-scan malformed metadata tolerance** - `--self-scan` now skips local
  distributions with incomplete package metadata instead of crashing on a
  malformed `.dist-info` entry.
- **Proxy sandbox runtime validation** - validates sandbox runtimes by command
  name so runtime enforcement errors fail on the intended executable boundary
  (#2349).
- **Graph live-edge serialization guard** - added regression coverage for live
  graph edge serialization so dense graph consumers keep stable relationship
  payloads (#2358).
- **Product path and monorepo scanning copy** - clarified scan/control
  plane/runtime positioning and monorepo scanning paths in public surfaces
  (#2357).

### CI
- **UI and SDK dependency refresh** - updated Next/React support packages,
  CodeQL action pins, and TypeScript SDK Node typings with green PR checks and
  current `main` CI evidence (#2330, #2331, #2340, #2341, #2342, #2343, #2346,
  #2360).

---

## [0.86.2] - 2026-05-07

Audit-readiness patch for the live dashboard/API release pass. This release closes the scan-contract, graph-serialization, gateway-transport, CI refresh, image tarball, API extras, MCP/HTTP contract, and gateway NetworkPolicy hardening items validated after `v0.86.1`.

### Added
- **Airgap image tarball entry point** - `agent-bom image --tar <path>` now scans local OCI/Docker tarballs without requiring a Docker daemon or registry pull path (#2327).
- **MCP-to-HTTP scan contract coverage** - regression coverage now asserts MCP scan output shape stays aligned with the HTTP scan path for shared scan internals (#2326).
- **Gateway component NetworkPolicy** - Helm now renders a gateway-specific default-deny egress policy with explicit DNS/upstream allowlist hooks instead of relying only on global policy coverage (#2328).

### Fixed
- **Strict scan request validation** - direct and source-triggered scan requests now reject unknown fields with 422 errors instead of silently dropping typoed inputs (#2319).
- **Dashboard protected-view UX** - protected graph/dashboard views now turn empty API-key and browser authorization-header failures into sign-in/forbidden states instead of raw DOM exceptions (#2319).
- **Graph API serialization readiness** - graph edges, attack paths, node detail relationships, diff metadata, and path query aliases now serialize consistently for dense graph consumers (#2323).
- **Gateway upstream transport guardrails** - SSE upstreams are rejected with an explicit configuration error instead of being relayed through an incompatible POST path; streamable HTTP upstreams keep working (#2322).
- **SQLite graph schema initialization race** - graph schema marker initialization is idempotent, preventing concurrent initializer failures in CI and tenant graph persistence (#2320).
- **First-run sample flag alias** - the first-run sample CLI now accepts the documented target alias consistently (#2321).
- **API extras diagnostics** - API startup dependency checks now report the missing import details instead of over-collapsing into a misleading extras message (#2325).
- **Ready-PR refresh loop** - stranded approved PRs now have a safer refresh path so branch updates do not freeze behind stale checks (#2324).

---

## [0.86.1] – 2026-05-06

Patch release alignment after the `v0.86.0` tag failed before publish at the MCP registry serialization gate.

### Fixed
- **MCP registry release serialization** — reformatted the bundled registry with the canonical Unicode-preserving serializer so the release gate no longer mutates `src/agent_bom/mcp_registry.json` at tag time.
- **Pre-tag registry serialization guard** — `scripts/check_release_consistency.py` now verifies MCP registry serialization stability during normal CI/pre-release checks, preventing this class of failure from reaching the tag workflow again.
- **Short-description limit guard** — release consistency now enforces the 100-character publish limit for the package short description before release workflows reach registry publication.

---

## [0.86.0] – 2026-05-03

AI-infra and supply-chain breadth release: ATLAS catalog wired through to dashboard, Snowflake Native App Phases 1–3 with DCM as a first-class IaC type, GPU cloud + driver/firmware coverage (AMD/Intel/NVIDIA, Lambda Labs / RunPod / Vast.ai / Crusoe / Nebius), Compliance Hub closed end-to-end (#1044), plus two new content scanners (SPDX licenses, dataset PII/PHI).

### Added
- **Compliance Hub series** — `compliance_hub.py` engine plus four ingestion adapters (SARIF / CycloneDX / CSV / JSON) and four hub API endpoints (`POST /v1/compliance/ingest`, `GET /v1/compliance/hub/findings`, `GET /v1/compliance/hub/posture`, `DELETE /v1/compliance/hub/findings`) so external scanner output lands in the same per-tenant posture surface as native scans. Closes #1044 (#2200, #2201, #2203, #2204).
- **Durable Compliance Hub backends** — SQLite and Postgres stores back the hub with tenant-scoped persistence and reserved-namespace tenant validation, replacing the in-memory placeholder (#2205).
- **MITRE ATLAS catalog refresh** — `atlas_fetch.py` pulls from `mitre-atlas/atlas-data` so the catalog stays current; CI guards against drift (#2215).
- **IaC → ATLAS mapping for AI infra** — Terraform / Helm / K8s findings annotate the matching ATLAS technique IDs so dashboards can pivot from infra control gaps to adversary technique coverage (#2216).
- **ATLAS coverage tile on dashboard** — `/compliance` page surfaces the bundled MITRE ATLAS catalog (version, curated-vs-upstream technique count, last-updated) so users can verify the catalog they are matching against (#2217).
- **Snowflake Native App Phase 1** — manifest, customer-approved access policy, DCM module, and tenancy boundary (#2210, #2220).
- **Snowflake Native App Phase 2** — Snowpark stored procedure that materialises Compliance Hub posture inside the customer's Snowflake account; results never leave tenant boundary (#2226).
- **Snowflake Native App Phase 3** — SPCS-hosted Next.js UI with service-role binding so customers run the full agent-bom dashboard inside Snowpark Container Services (#2227).
- **Snowflake DCM as first-class IaC type** — DCM scripts get a dedicated parser and finding namespace alongside Terraform/Helm/K8s/CFN/Pulumi (#2218, #2222).
- **DCM fullstack wiring + IAM-to-agent graph edges** — DCM resources flow through the scan pipeline into the graph; IAM principals get a `MANAGES` edge to derived agents (#2233).
- **IaC scanner context — two-gate dispatch, capability verdicts, deployment-aware** — scanners now carry deployment context so the verdict reflects "what this manifest actually deploys" rather than syntactic posture (#2223).
- **AMD advisory scanner** — AMD PSIRT advisory ingestion + GPU driver CVE mapping + K8s GPU compound rules (#2224).
- **AMD PSIRT live-feed fetcher** — keeps AMD advisory data fresh; falls back to a checked-in static seed if the upstream feed is unreachable (#2230).
- **AMD/Intel driver CVE gates + Intel advisory feed + K8S-036** — per-node driver checks for both vendors plus a K8s rule (`K8S-036`) for `nvidia-device-plugin` RBAC scope (#2232).
- **Intel i915/xe driver CVE gate** — per-node check for CVE-2023-22655 / CVE-2023-25546; reads `/sys/module/i915/version` or `/sys/module/xe/version` via `kubectl exec`, falls back to `uname -r` (#2236).
- **NVIDIA DGX/HGX firmware + BMC advisories** — `firmware_advisory.py` ships a 6-CVE NVIDIA CSAF seed (3× H100 BMC/CLI critical/high, DGX A100 SBIOS, ConnectX-6 DoS, DGX Station A100 OOB write); per-node product mapping via GPU-model labels; surfaces through `GpuInfraReport.firmware_findings` and `risk_summary.firmware_cve_count` (#2236).
- **Container image SBOM (RunPod / Vast.ai)** — `container_sbom.py` fetches Docker Hub registry v2 metadata (manifest digest, config labels, layer size). Emits `UNPINNED_TAG`, `NO_SBOM_ATTESTATION`, `STALE_IMAGE` (>180d), `MISSING_PROVENANCE` findings; offline-safe and graceful on token/manifest failures; per-process `lru_cache` so duplicate pods share one Docker Hub round-trip (#2236).
- **GPU cloud provider discovery** — Lambda Labs, RunPod, Vast.ai, and Crusoe added to the cloud catalog; agents emerge with `cloud_origin.provider` set to the right vendor (#2229).
- **Nebius InfiniBand training job discovery** — Nebius training jobs and their InfiniBand fabric scope are discovered as agents (#2231).
- **SPDX license file scanner** — detects `LICENSE` / `COPYING` files and SPDX source-header markers across the inventory; results feed the existing license posture surface (#2234).
- **Dataset PII/PHI content scanner** — CSV / JSON / JSONL content scanner that flags datasets containing PII/PHI columns or values (#2235).
- **Identity and naming contract hardening** — locks the platform identity / canonical-name vocabulary so downstream surfaces stop drifting (#2207).
- **`summary.unique_packages` field on JSON output** — disambiguates occurrence count from the deduplicated package count so dashboards stop double-counting transitive duplicates (#2199).
- **`summary.total_packages` semantics clarified** — documented as occurrence-shaped to match the existing wire format and pair with `unique_packages` (#2199).

### Fixed
- **`--self-scan` walks the active venv** — `_build_self_scan_inventory` now uses `importlib.metadata.distributions()` so transitive deps appear in the inventory (#2197).
- **Dashboard splash kind classification on `/compliance` and `/vulns`** — auth and forbidden errors now render distinct copy instead of the generic "Cannot connect" splash (#2199).
- **v0.85.0 multi-persona audit P1 items** — close-out doc fixes for the persona-targeted README/docs surfaces flagged in the v0.85.0 review (#2208).
- **Compliance Hub posture aggregates all 15 frameworks** — posture endpoint no longer truncates at the first frameworks; CHANGELOG synced in the same PR to match shipped behaviour (#2221).
- **Docker Hub short description trimmed to 100-char API limit** — release publish step no longer 422s on the description sync (#2225).

### Documentation
- **`--self-scan` flag reference** added to the CLI docs (#2202).
- **Compliance SVG framework alignment** with `COMPLIANCE_FRAMEWORKS` so the diagram and code list never drift (#2206).
- **Policy-precedence + runtime-reference consolidation** — single source of truth for how runtime gating, firewall, and proxy policies interact (#2209).

### CI
- **DCM scanner self-check** — meta-recursive job runs the DCM scanner against the agent-bom-shipped DCM manifests on every PR (#2228).

---

## [0.85.0] – 2026-05-02

Two new product surfaces (inter-agent firewall + per-run discovery envelope) plus four audit-driven defect fixes from the v0.84.6 hands-on review.

### Added
- **Inter-agent firewall** — tenant-scoped policy engine for agent → agent delegation. Pairwise + role-tag rules with `allow` / `deny` / `warn-only` decisions, dry-run mode for safe rollouts, hot-reloadable policy file. Decisions emit through the existing `/v1/proxy/audit` HMAC-chained audit relay. CLI: `agent-bom firewall validate / list / check`. Runtime card on the gateway dashboard tab. Issue #982 closed by #2188 / #2189 / #2190 / #2191.
- **Per-run discovery envelope** (#2083) — every discovered Agent now carries a trust contract recording the actual scan mode, explicit scope, IAM/API permissions exercised, and redaction posture for that run. Locked enums (`scan_mode`, `redaction_status`), schema-versioned (`envelope_version: 1`), surfaced through the existing `/v1/agents` API and a new `DiscoveryEnvelopeCard` on agent detail with a data-residency note. Wired on AWS, GCP, Azure, CoreWeave, Nebius, Snowflake, Databricks, MLflow, W&B, HuggingFace, OpenAI, and Ollama. Cross-provider least-privilege + redaction lock-in matrix tests every catalog entry against an explicit read-only verb allowlist (`Get` / `List` / `Describe` / `Search` / `Read` / `Select` / `View` / `Retrieve` / `Show` / `Fetch` / `Scan` / `watch` / `GET` / `HEAD` / `OPTIONS`). Issue #2083 closed by #2192 / #2193 / #2194 / #2195.
- **Diagrams alignment** — engine-internals and compliance SVGs realigned to canonical product counts (15 ecosystems, 14 + AISVS frameworks, 29 MCP clients, 36 MCP server tools, 26 output formats, 419 test files); OpenClaw / ClawHub framed as distribution surfaces in `integrations/openclaw/README.md`. Issue #2150 closed by #2187.

### Fixed
- **SCIM DELETE removes users from default listing** (P1 IdP-blocker, audit #2196) — `deactivate_user` flips `active=False` and bulk `list_users` now excludes deactivated users, matching Okta/Azure AD deprovisioning expectations. Precise lookups by `userName` / `externalId` / `id` keep finding deactivated users so admins can verify the deactivation landed; `?filter=active eq <bool>` is the new admin-audit primitive. Re-creating a deprovisioned `userName` still 409s.
- **`--allow-insecure-no-auth` no longer silently overridden by SCIM bearer** (P2 audit #2196) — `_enforce_auth_defaults` recognises `AGENT_BOM_SCIM_BEARER_TOKEN` as a valid auth path. When the flag is set together with any auth method, a yellow warning to stderr names the active method instead of pretending the flag disabled auth.
- **Dashboard "Cannot connect" splash distinguishes auth from network errors** (P2 audit #2196) — `ApiOfflineState` takes a `kind: "network" | "auth" | "forbidden"` prop; pages classify thrown errors via `ApiAuthError` / `ApiForbiddenError`. Auth/forbidden cases get distinct copy ("Sign in to view the dashboard" / "This account doesn't have access").
- **`POST /v1/auth/keys/{id}/rotate` accepts empty body** (P3 audit #2196) — body now optional; defaults applied silently for missing or `{}` payloads.
- **Strict MCP tool argument contract** (P1 audit #2197) — every registered tool's JSON schema now sets `additionalProperties: false`, and a runtime guard at the tool-manager call boundary rejects calls with unknown argument keys before FastMCP's Pydantic validation silently drops them. Pre-fix, AI agents passing typo args (`Version` capital, `frob`, etc.) got false-clean verdicts on the pre-install gate.
- **Skill trust verdict split into provenance + content axes** (P1 audit #2197) — `TrustAssessmentResult` now carries `provenance_verdict` (signed? install metadata complete? source URL?) and `content_verdict` (behavioural risk signals from the audit) alongside the legacy `verdict`. Pre-fix, three legitimate cybersecurity playbooks were marked `malicious` purely because they were unsigned and lacked a frontmatter `source:` URL despite zero detected risk signals (~80% false-positive rate on real security skill trees).
- **`--self-scan` walks every venv distribution** (P2 audit #2197) — `_build_self_scan_inventory` now uses `importlib.metadata.distributions()` so transitive deps appear in the inventory. Pre-fix, only ~23 declared deps were scanned vs ~66 actually installed.
- **Proxy stderr sandbox warning is single-emission** (P3 audit #2197) — the duplicated `sys.stderr.write(warning)` is dropped; `logger.warning(warning)` is the single source. The structured `mcp_execution_posture` audit event still carries the same posture detail in machine-readable form.

### Documentation
- New `docs/AGENT_FIREWALL.md` — schema reference, gateway integration, proxy fast-path, dashboard overlay, 4-PR roadmap.
- New `docs/DISCOVERY_ENVELOPE.md` — schema reference, locked vocabulary, producers table, API + UI surface, lock-in matrix.

---

## [0.84.6] – 2026-05-02

### Added
- **CLI startup banner** — running `agent-bom` with no subcommand now renders a branded banner with three quick-start commands and a docs pointer (#2181).
- **Verdict-led compact summary** — `agent-bom scan` ends with a one-line posture verdict plus inventory; the previous detailed configuration-posture panel is preserved behind `--verbose` (#2184).
- **Severity-coloured scan closer** — the trailing line now renders a coloured `Scan complete — N critical · N high · …` breakdown instead of a generic finding count (#2181).
- **Findings header label** — when priority filtering hides rows, the table header reports `Findings (X of Y shown · Z hidden)` so the elision is visible (#2181).

### Fixed
- **Severity closer rendered empty on Python 3.13** — `Severity(str, Enum)` `str()` semantics changed; the closer now reads `Severity.value` so the breakdown renders content on every supported Python (#2185).
- **npm SemVer pre-release tag handling** — `compare_version_order` now strips `-canary.N`, `-beta.N`, `-rc.N`, etc. before PEP 440 parsing so npm pre-releases no longer fall through to the conservative "affected" verdict (e.g. CVE-2023-46298 false positive on `next@16.2.4-canary.13`) (#2182).
- **Stacked progress lines under interleaved log warnings** — scanner warnings now flow through Rich during the progress block, so spinners stop double-rendering when GHSA/OSV emit warnings mid-scan (#2183).
- **OSV-first GHSA UX** — the "GITHUB_TOKEN not set" / "limited to N unauthenticated lookups" notes are now informational only and no longer surface as scan warnings; OSV mirrors GHSA within ~24h, so the unauthenticated path is the default for typical use and a `GITHUB_TOKEN` is only needed for fresh-CVE turnaround under 24h (#2181).

---

## [0.84.5] – 2026-05-01

### Added
- **MCP package version provenance** — packages now carry canonical `version_source` and `confidence` metadata, structured evidence, version conflicts, and resolved-version timestamps across scanner data, graph/API outputs, SARIF, SBOM formats, attack-flow exports, SVG graph output, and dashboard surfaces.
- **Floating MCP command resolution evidence** — `npx` and `uvx` package detection now upgrades floating commands from low-confidence registry fallback to higher-confidence local tool-cache evidence when downloaded package metadata is available.

### Fixed
- **Focused CLI flag parity** — `agent-bom secrets` and `agent-bom skills scan` now accept `--no-color`, `--log-json`, and `--log-file` consistently with the rest of the CLI.
- **Version provenance evidence redaction** — package-version evidence now sanitizes local package paths before findings are emitted.
- **Skills quiet output** — `agent-bom skills scan --quiet` suppresses extra prose without dropping the findings table.

---

## [0.84.4] – 2026-05-01

### Fixed
- **Deterministic release registry gate** — tag workflows now verify committed registry freshness and local JSON serialization stability without running live registry syncs against moving external catalogs.
- **Patch release alignment** — bumped release surfaces from the failed `v0.84.3` tag to `v0.84.4` after the registry gate proved the live-sync check was nondeterministic.

---

## [0.84.3] – 2026-05-01

### Fixed
- **Release docs deployment guard** — GitHub Pages deployment now only runs from `refs/heads/main`, so tag-triggered release builds can verify docs without entering the protected Pages environment.
- **Patch release alignment** — bumped release surfaces from the cancelled `v0.84.2` tag to `v0.84.3` after the tag workflow was cancelled before package publication.

---

## [0.84.2] – 2026-05-01

### Fixed
- **Release tag gates** — reusable docs builds now skip GitHub Pages deployment when invoked by the tag release workflow with `deploy: false`, preventing protected Pages environments from blocking package publication.
- **MCP registry sync determinism** — all bundled registry writers now share Unicode-preserving JSON serialization, preventing release-gate churn from rewriting capped descriptions between literal `…` and escaped `\u2026`.
- **Bundled registry freshness** — refreshed the committed MCP registry to 658 servers so the strict `sync-all` release gate can pass without weakening freshness checks.

---

## [0.84.1] – 2026-05-01

### Fixed
- **Gateway auth and GHSA rate-limit hardening** — gateway API-key verification now fails closed on key-store errors, and unauthenticated GHSA enrichment is capped with upfront warnings so CLI/API/dashboard scans do not pause for long GitHub advisory backoff storms.
- **Extension registry safety** — the extension entry-point registry is documented and explicit, keeping plugin-style imports opt-in instead of silently importing installed package code during security scans.
- **CLI documentation and exit-code alignment** — grouped CLI docs now match the 30+ command surface, usage errors consistently return exit code 2, and release checks guard future CLI reference drift.
- **Graph export parity** — CLI Cytoscape, Graph HTML, Mermaid, GraphML, Cypher, and API graph paths now surface conservative credential → tool `reaches_tool` evidence consistently.
- **Dashboard scan polling** — the scan detail UI now polls a lightweight status endpoint during async scans and fetches the full result only once at completion, avoiding repeated multi-MB `/v1/scan/{id}` payloads.
- **CLI error contracts** — listener ports now reject privileged or invalid values before socket bind, and malformed inventory, VEX, policy, and ignore files fail loudly with actionable parser messages instead of raw tracebacks or silent skips.
- **Pre-release output polish** — clean scans now describe config-posture gaps without contradicting `SECURITY POSTURE: CLEAN`, project-scoped agents render with human-readable labels, and CSV inventory ingestion logs skipped empty package rows.
- **Delta gate artifact consistency** — delta-mode filtering now happens before report rendering so JSON/SARIF artifacts and CI exit gates reflect the same new-only finding set.
- **UI E2E production parity** — Playwright now runs against a staged standalone bundle that mirrors the container runtime, preventing hydration checks from passing only in dev mode.
- **Release registry freshness** — the bundled MCP registry is refreshed for the patch release, release gates now enforce freshness before tagging, and registry descriptions are capped at 100 characters across sync paths to protect catalog/UI consumers.

---

## [0.84.0] – 2026-04-30

### Added
- **Graph capability reachability** — graph construction now emits `EXPLOITABLE_VIA` edges from affected packages/vulnerabilities to reachable MCP tool capability nodes, closing the package → MCP server → tool → agent attack-path chain for graph consumers.
- **Cloud discovery and ingest skills** — bundled skills now cover Azure, GCP, Snowflake, and pushed-inventory ingest workflows alongside the existing AWS discovery path, with the same guardrail contract, provenance requirements, and read-only defaults.
- **MCP server resources, prompts, and capability metadata** — the server card now advertises 36 read-only tools, 6 resources, 6 workflow prompts, and machine-readable capability classes so agents can choose the right workflow without guessing.

### Changed
- **Human reports and graph risk state** — Markdown, HTML, compact console output, and graph nodes now render unified non-CVE findings such as MCP blocklist hits with matching severity, evidence, remediation, and blocked/warning state.
- **Snowflake and self-hosted deployment path** — Snowflake POV docs, EKS deployment profile, BYO Postgres guidance, and deployment navigation were tightened around the current operator-pull and customer-managed data-store model.
- **MCP documentation and metrics alignment** — MCP docs, server-card descriptions, product metrics, Glama/MCP registry manifests, Docker/Helm references, OpenClaw skill metadata, and README release refs now align to the v0.84.0 surface.

### Fixed
- **Bundled skill contract enforcement** — skill guardrail metadata is now regression-tested so new skills must declare credential handling, data flow, file access, network endpoints, invocation policy, and verification posture.
- **Posture headline calibration** — compact output no longer pairs high/critical policy findings with a misleading strong/clean posture headline.
- **Release-surface drift** — package metadata, Helm chart/app versions, image pins, registry manifests, skill versions, and verification docs were bumped together for the v0.84.0 release.

---

## [0.83.4] – 2026-04-30

### Added
- **Snowflake scope-zero operator-pull adapter** — Snowflake now joins AWS, Azure, and GCP as a first-class operator-pushed inventory path, letting teams collect Cortex/Snowpark/Snowflake AI inventory inside their own boundary and explicitly decide whether to hand the canonical JSON to agent-bom for findings, graph, policy, and exports.
- **MCP registry freshness gate** — `agent-bom registry status` now reports stale/never-synced registry state with `needs_refresh` and `recommended_action`, and `--fail-on-stale` gives release, demo, and CI pipelines a hard gate for bundled MCP intelligence freshness.

### Changed
- **Pre-pilot proxy/gateway hardening** — SSE proxy policy checks now match stdio/gateway policy scope, gateway upstream handling has bounded resilience, and remote runtime HTTP mode requires explicit auth unless an operator opts into insecure local behavior.
- **Self-hosted deployment contract** — Helm and deployment docs now state the BYO Postgres contract clearly, including the expected `AGENT_BOM_POSTGRES_URL` secret shape for production profiles.
- **Fleet and scanner state isolation** — fleet graph nodes preserve endpoint identity for same-named agents across devices, and local database scan preference is threaded through `ScanOptions` instead of shared module state.

### Fixed
- **Discovery provenance in exports and UI** — SARIF, OCSF, CycloneDX, and dashboard trust surfaces now retain sanitized discovery provenance, permissions-used, and scan-mode context so auditor-facing outputs match JSON/API evidence.
- **Release/readiness alignment** — README, site docs, OpenClaw skills, Glama/MCP registry manifests, Docker/Helm references, and package metadata are aligned for the v0.83.4 release surface.

---

## [0.83.3] – 2026-04-30

### Fixed
- **Wheel inventory schema packaging** — `inventory.schema.json` now ships inside the installed `agent_bom` package, so PyPI users can run `agent-bom agents --inventory ...`, operator-pull adapters, and skill-mediated inventory flows without a source checkout.
- **Inventory error exits** — missing inventory schema errors are now surfaced as explicit `--inventory` parameter failures with exit code 2 instead of falling through generic CLI handling.
- **Interactive GHSA checks** — unauthenticated single-package GHSA rate-limit responses now fail fast instead of pausing for the fleet-scan backoff window, while multi-package scans preserve the bounded retry behavior.

### CI
- **Wheel content guard** — PR and release package builds now fail if required JSON schema package data is missing from the wheel.

---

## [0.83.2] – 2026-04-30

### Fixed
- **Release gate determinism** — the tag publish workflow now uses `pip-audit` as the hard Python dependency release gate and keeps `agent-bom` self-scan SARIF as bounded evidence without opportunistic DB refresh, preventing third-party enrichment drift from cancelling a release after the build and container gates have already passed.

---

## [0.83.1] – 2026-04-29

### Fixed
- **Release workflow stability** — reusable docs deployment now honors `deploy: false` when invoked by the release workflow, preventing a tag release from trying to deploy GitHub Pages as part of package publishing.
- **Post-merge SAST time budget** — post-merge source analysis now uses the bounded `agent-bom code` analyzer and converts its JSON to SARIF, preserving Security tab upload coverage without running the broad scan pipeline.

---

## [0.83.0] – 2026-04-29

### Added
- **Scope-zero discovery and pushed inventory workflows** — operator-pull adapters now let teams collect AWS, Azure, and GCP inventory inside their own boundary, emit canonical inventory JSON, and choose whether to stop at the file boundary or explicitly hand the inventory to `agent-bom agents --inventory` for findings, graph, policy, and exports.
- **Agentic skill surfaces** — bundled AWS discovery and vulnerability-intelligence skills define standalone, guardrailed workflows for AI-agent users. Skills default to explain/discover/check modes and make any scan, push, or export handoff explicit.
- **Discovery provider contracts** — `/v1/discovery/providers` and the extension registry contract now describe provider scan modes, permissions used, network boundaries, redaction posture, and scope-zero extension modes without loading third-party provider code by default.
- **End-to-end discovery provenance** — inventory, packages, findings, graph exports, SARIF, UI surfaces, and pushed results now preserve discovery provenance, mapping method, confidence, lifecycle fields, cloud origin, permissions used, and reachability context through the canonical model.
- **Extension entry-point registries** — cloud providers, connectors, and inventory parsers now have opt-in entry-point registry foundations for plugins and SDK-built integrations while preserving built-in behavior when extension loading is disabled.

### Changed
- **Cloud discovery normalization** — AWS, Azure, GCP, Databricks, Snowflake, CoreWeave, Nebius, Hugging Face, OpenAI, W&B, and MLflow assets now use service/resource-type-aware `cloud_origin` envelopes, lifecycle fields, status, canonical package PURLs, and sanitized warning boundaries.
- **Scanner and ingestion robustness** — scanner options are isolated per scan, AWS provider discovery runs service collectors in parallel, external scanner ingestion preserves advisory metadata, and cross-environment correlation is bucketed by account/project context for fleet-scale scans.
- **Agentic architecture documentation** — docs now explain the product/skill/MCP layering, secure handoff modes, subagent delegation boundaries, and how teams can use agent-bom locally, in CI, self-hosted, cloud-read-only, pushed inventory, or through AI-agent workflows.

### Security
- **Launch metadata redaction** — MCP launch args, URLs, runtime errors, audit details, graph metadata, SARIF locations, CycloneDX properties, AI prompts, pushed results, and UI fallbacks are sanitized before storage, export, display, or prompt construction.
- **MCP intelligence and gates** — MCP intelligence now carries confidence, source, recommendation, references, and remediation metadata; non-CVE findings are rendered in compact output, SARIF, graph/API surfaces, and `--fail-on-severity` gates.
- **Proxy and scanner hardening** — proxy audit hash chains use a stable path-derived lock, server-to-client JSON-RPC reads are bounded, Docker/Podman MCP image commands scan through the image inventory path or fail closed, registry fallback matching is boundary-aware, and GHSA advisory lookups paginate with rate-limit handling.

### Fixed
- **GitHub Pages deployment** — docs deploy on pushes by default again, preventing stale Pages output after successful docs builds.
- **PR gate SARIF contract** — AppSec PR-gate SARIF output now uses real self-scan output and fails fast when focused modes cannot produce valid SARIF.
- **Stranded PR handling** — retrigger automation and lockfile-normalization CI were hardened to reduce frozen PRs caused by GitHub's token anti-loop behavior.

---

## [0.82.3] – 2026-04-28

### Added
- **Reachability-aware blast radius** — the graph-walk dependency-reach engine that shipped in v0.82.0 is now wired into `BlastRadius` scoring and the dashboard. New `BlastRadius.graph_reachable` / `graph_min_hop_distance` / `graph_reachable_from_agents` fields are populated by `agent_bom.graph.blast_reach.apply_dependency_reachability_to_blast_radii` during the analysis phase of every scan; `calculate_risk_score()` applies a small contextual nudge (+0.5 reachable, −0.5 unreachable, env-overridable via `AGENT_BOM_RISK_REACHABLE_BOOST` / `AGENT_BOM_RISK_UNREACHABLE_PENALTY`) so reachable findings rise above otherwise-equivalent unreachable ones in triage. The vulns dashboard renders a "Reachable · N hops" / "Unreachable" badge next to KEV. Engine failures degrade to a no-op so a graph bug never breaks the scan path. Closes the v0.82.2 honest-gap on engine-vs-surfacing (#2040).
- **KEDA-driven autoscaling on the control-plane API tier** — new `controlplane-api-keda-scaledobject.yaml` Helm template + `examples/eks-keda-values.yaml` production preset. Three default Prometheus triggers tuned to bursty scanner workloads: rate-limit pressure, p99 latency, and the new `agent_bom_scan_jobs_active` gauge. The static CPU/memory HPA is suppressed when KEDA is enabled so two HPAs never fight over the same Deployment. Closes the EKS scoring audit's "HPA custom metrics not wired" gap (#2035, #2037).
- **`agent_bom_scan_jobs_active` Prometheus gauge** — first-class queue-depth gauge bumped at `enqueue_scan_job` and decremented in `_run_scan_sync`'s `finally` block. Floored at zero so an instrumentation gap absorbs gracefully rather than producing a negative scrape. Records `record_scan_completion(status)` at the same site, wiring up the previously-orphaned counter (#2037).
- **Clustered Postgres scale evidence harness** — `scripts/run_postgres_scale_evidence.py` drives the real `agent_bom.api.postgres_*` modules at increasing scale (audit append, job put/get) with `--replicas N` for `ProcessPoolExecutor` fan-out so the run captures pool contention + advisory-lock cost, not just single-process throughput. New `.github/workflows/postgres-scale-evidence.yml` runs it manually + weekly against a `postgres:16-alpine` service container and uploads JSON evidence as a 90-day artifact. PRs do NOT run it — too slow and tuning-sensitive to gate on. Closes the v0.82.2 SLO doc's "no published clustered Postgres scale benchmark" gap (#2038).
- **Auto-retrigger workflow for stranded PRs** — `.github/workflows/auto-retrigger-stranded.yml` runs `scripts/retrigger_stranded_pr.sh` on a `*/5 * * * *` cron against every open non-draft PR whose current head SHA has zero `Lint and Type Check` runs. Permanently neutralises the GITHUB_TOKEN-authored "Update branch" anti-loop suppression that intermittently stranded #1996, #2030, #2031, #2034, #2035 in this release cycle (#2036).
- **Per-framework compliance coverage table** — `docs/ARCHITECTURE.md § Coverage per framework` publishes the bundled-control counts vs. source-standard size for all 14 frameworks. README + `SECURITY_ARCHITECTURE.md` + `MCP_SECURITY_MODEL.md` + `MCP_ERROR_CODES.md` link to it. Closes the v0.82.2 honest-gap on compliance breadth (#2032).
- **Two-image deployment guidance** — new `docs/ENTERPRISE_DEPLOYMENT.md § Container images — do I need both?` section with verifiable code refs (`server.py:685-708` mounts `ui_dist/`, `pyproject.toml:189` ships `ui_dist/**` as wheel package data). Single-host pilots only need `agentbom/agent-bom`; the second image is for Kubernetes deployments that scale / restrict / ingress the UI tier independently (#2039).
- **Merge-queue runbook + helper script** — `docs/operations/CI_RUNBOOK.md § Permanent fix options` now documents the supported UI-only path for enabling merge queue, with `scripts/enable_merge_queue.sh --check` to inspect current ruleset state (#2034).

### Changed
- **UI TypeScript is now strict on `noUncheckedIndexedAccess` + `exactOptionalPropertyTypes`** — closes the long-running tracking issue #1967. Every array/Record index access yields `T | undefined` and every `?:` field is treated as "absent OR T". 60 violations fixed across the UI tree, mostly via type widening at internal boundaries plus conditional-spread for 3rd-party React-Flow / Recharts integrations. ESLint already enforced `no-floating-promises` and `no-explicit-any` as `error`; `lightningcss` was already in `devDependencies`; UI version was already lockstep with the platform release process (#2030, #2033).
- **Mypy strict phasing — four more API store modules** — `fleet_store`, `idempotency_store`, `schedule_store`, `scim_store` added to the per-module strict override list in `pyproject.toml`. Generic `dict` annotations widened to `dict[str, Any]`, `_local.conn` returns surfaced as concrete `sqlite3.Connection`, pydantic `model_validate_json` and platform-invariant helpers wrapped to satisfy `warn_return_any` under `--follow-imports=skip`. Refs #1969 (#2031).

---

## [0.82.2] – 2026-04-27

### Fixed
- **UI image multi-arch publish** — `ui/Dockerfile` hard-pinned `lightningcss-linux-x64-gnu@1.32.0`, which broke the arm64 leg of the v0.82.1 release pipeline's `Publish UI image` job (`docker buildx --platform linux/amd64,linux/arm64`) with `EBADPLATFORM`. The fix consumes the `TARGETARCH` build arg buildx already injects and installs the matching prebuilt only (`lightningcss-linux-arm64-gnu` for arm64, `lightningcss-linux-x64-gnu` for amd64). v0.82.1 published the Python package, main API/CLI image, Helm chart, Sigstore signature, SLSA provenance, and CycloneDX SBOM successfully; only the standalone dashboard UI image at `agentbom/agent-bom-ui:0.82.x` was missing. v0.82.2 republishes that image for both architectures (#2025).

---

## [0.82.1] – 2026-04-27

### Fixed
- **Dashboard build under `output: "export"`** — `ui/app/graph/page.tsx` was using `export const dynamic = "force-dynamic"`, which is incompatible with Next 16's static export and aborted the v0.82.0 release pipeline at the Build/dashboard step (PyPI + Docker Hub publish jobs were skipped). Replaced with `next/dynamic({ ssr: false })`, the standard pattern for client-only components (`@xyflow/react` needs DOM) inside a static export. Re-enables the release pipeline; v0.82.0 stayed a no-op tag with no published artifacts.

---

## [0.82.0] – 2026-04-27

### Added
- **Graph-walk dependency reachability engine** — new `agent_bom.graph.compute_dependency_reach` (in `src/agent_bom/graph/dependency_reach.py`) runs BFS from every agent node along `USES` / `DEPENDS_ON` / `CONTAINS` / `PROVIDES_TOOL` edges and reports per-package `min_hop_distance` + `reachable_from` plus per-vulnerability summaries. **Engine half only.** Surfacing reach in blast-radius scoring and the dashboard follows in a separate PR; this release does not change scoring behaviour. Closes the engine half of #1896 (#2009).
- **JSON Schema (draft 2020-12) generated from API Pydantic models** — `scripts/generate_v1_schemas.py` walks every public model in `agent_bom.api.models`, emits `docs/schemas/v1/<Model>.json` per model plus an `index.json` manifest. CI gates the drift via `--check`. SDK consumers can codegen against the published surface. Closes #1963 (#2007).
- **Row-virtualized agent list pages** — `ui/app/agents/page.tsx` configured + installed agent cards now render through `@tanstack/react-virtual`'s `useVirtualizer` with `measureElement` for variable-height rows. Enterprise estates with thousands of agents no longer render every card flat. Vitest covers the windowing math. Refs #1955 — agents half closed; vulns table flat path is already paginated, grouped path windowing tracked separately (#2006).
- **Cross-environment correlation framework + AWS Bedrock matcher** — local agents and cloud-discovered Bedrock runtimes are now matched on the strict triplet of cloud account ID + region + model ID. Strong matches emit `CORRELATES_WITH` graph edges; partial matches stay visible as `POSSIBLY_CORRELATES_WITH` with a `matched_signals` evidence list so reviewers can see candidates without the platform conflating them. Phase 1 of #1892; Phase 2 (Azure OpenAI / Functions, #1992) and Phase 3 (GCP Vertex / Cloud Run, #1993) plug into the same dispatch.
- **Azure OpenAI cross-environment matcher** — extends the cross-environment correlation framework to Azure OpenAI deployments. Strict triplet is subscription ID + Cognitive Services account name + deployment name; explicit `OPENAI_API_TYPE=open_ai` disqualifies the agent so an Azure-shaped match never fires for public-OpenAI clients. Cloud discovery for Azure OpenAI now emits a normalized `cloud_origin` envelope so the matcher has structured identity to compare against. Phase 2 of #1892 (#1992).
- **GCP Vertex AI cross-environment matcher** — extends the cross-environment correlation framework to GCP Vertex endpoints. Strict triplet is project ID + location + endpoint ID; the project-ID format gate rejects arbitrary strings (e.g. "test", emails) from counting as a project match. The endpoint env value is also accepted as a full Vertex resource path so a single IaC-supplied identifier surfaces all three signals. Phase 3 of #1892 (#1993).
- **Cloud origin lineage in the unified graph** — agents discovered with cloud metadata now promote `cloud_principal`, `cloud_resource`, and direct principal→agent edges so single-hop reachability queries no longer have to traverse the intermediate cloud_resource node.
- **GPU and k8s GPU promotion** — GPU containers and Kubernetes GPU clusters now flow into the unified graph alongside the rest of the inventory.
- **Static multi-agent topology edges** — framework-level agent topology is now materialized as graph edges so reviewers can see which agents delegate to which.
- **System prompt and MCP prompt inventory** — system prompts and MCP server prompts are now captured as policy evidence and surfaced through the standard inventory paths.
- **AI observability SDK inventory** — observability SDKs are detected and recorded as managed inventory.
- **MCP stable error envelope** — MCP responses now carry stable `code` / `category` / `details` / `schema_version` fields and a published API parity matrix so SDK consumers can branch on machine-readable errors.
- **Vanilla EKS production preset** — `deploy/helm/agent-bom/examples/eks-vanilla-values.yaml` ships a production-shaped preset for self-hosted EKS rollouts.
- **Customer secret rotation adapter evidence** — secret rotation adapters now emit deterministic evidence so operators can prove a managed key was rotated by their KMS, not the platform.
- **Native control-plane mTLS fallback** — the API can terminate mTLS itself when no mesh or front proxy is available, with a posture surface on `/v1/auth/policy`.
- **Frontend API error taxonomy + GET caching/dedup** — the dashboard API client now exposes a typed error taxonomy and dedupes/caches GET requests with prefix-scoped invalidation.
- **Columnar CIS benchmark trend aggregation** — CIS results persist into a fact table dimensioned by cloud × section × status × severity × time bucket, with a new `/v1/compliance/cis/trends` endpoint and AWS/Azure/GCP cross-cloud fixtures so operators can graph drift over time. Closes #1832 (#2013).

### Changed
- **Tenant quota enforcement is now atomic per tenant** — new `tenant_quota_guard(tenant_id, *checks)` context manager in `agent_bom.api.tenant_quota` holds a per-tenant `threading.Lock` (single-process atomicity) **and**, when `AGENT_BOM_POSTGRES_URL` is set, a session-scoped `pg_advisory_lock` keyed on `sha256(tenant_id)` for cross-replica atomicity. Wraps the (check + insert) pair in `scan`, `schedules`, `observability/push`, `scheduler-trigger`, and `fleet-sync` route handlers so concurrent requests serialise per tenant and the second caller sees the first caller's row in its check (audit-4 #2008 + audit-5 PR-B #2011).
- **Workflow timeout coverage** — every job in `.github/workflows/` now declares `timeout-minutes`, including reusable-workflow callers (`uses:`) which were silently inheriting the 360-minute GitHub default. New `scripts/check_workflow_timeouts.py` gates drift in CI (#2008, #2010).
- **Dependabot UI lockfile workflow** — `npm run lock:normalize` was replaced with the inline `npm install --package-lock-only --ignore-scripts` so a Dependabot branch can't redefine the script under the privileged `pull_request_target` token.
- **Centralised tenant resolution for CLI and MCP** — CLI and MCP entry points now resolve tenant id through one shared helper instead of per-surface ad-hoc logic.
- **Backpressure posture surfaced on `/v1/auth/policy`** — the operator policy endpoint now reports adaptive backpressure state (paths, p99, retry-after) alongside the auth and rate-limit posture.
- **CSP source-of-truth centralised** — `ui/next.config.ts` and `ui/vercel.json` now share one CSP definition; `script-src 'unsafe-inline'` is temporarily restored pending the hash-pinning collector.
- **Docker compose deployment** — platform compose files now use Docker secrets for Postgres credentials and align healthchecks across services.
- **Docker base alignment** — runtime images now use LTS base versions and the build pipeline gates on the Glama and image-policy checks.
- **Floating reference policy** — references to mutable upstream tags are now disallowed in build inputs by automated policy.
- **Postgres sizing guidance + weekly scale-evidence regen** — `docs/perf/` documents `pg_size_pretty` sizing for 1k/5k/10k estates and a scheduled CI run keeps `docs/perf/results/` fresh.
- **Generated `AGENT_BOM_*` env reference** — the env-var reference is now generated from `config.py` and CI fails if the doc drifts from the source.

### Fixed
- **Graph `add_edge` no longer drops second-add evidence on dedup** — when the builder adds the package-path edge first and the blast-radius edge second for the same `(source, target, relationship)`, the second edge's `evidence` dict (cvss, epss, kev, attack tags) is now merged into the kept edge instead of being silently discarded. Kept side wins on key conflicts so existing order-of-arrival semantics for shared keys are preserved (audit-5 PR-A #2010).
- **`_resolve_affected_server_ids` intersection collapse is now logged** — the narrow-by-server / narrow-by-agent intersections silently emptied when the named filter and the package-path candidates were disjoint. A debug log now surfaces report inconsistency to operator logs without changing the production narrow-by-all-filters semantics (audit-5 PR-A #2010).
- **SAML relay-state cleanup runs on issue too** — `_new_saml_relay_state()` previously inserted into `_SAML_RELAY_STATES` but never swept expired entries, letting an attacker who issued nonces but never completed the SAML round trip grow the in-memory map unbounded. Sweep on issue too (audit-5 PR-A #2010).
- **`release.yml` docs-site reusable caller missed timeout** — the audit-4 sweep added `timeout-minutes` to 29 jobs but skipped `docs-site` because the gate's `_is_reusable_caller()` helper returned `True` for any job with `uses:`. Reusable callers actually need their own timeout (the called workflow's per-job timeouts don't bound the caller; GitHub's default is 360 minutes). Gate fixed + `docs-site` now declares `timeout-minutes: 20` (audit-5 PR-A #2010).
- **Release and post-merge job timeouts** — every release-pipeline and post-merge-self-scan job now has an explicit `timeout-minutes`; runaway jobs no longer hold scarce runners.
- **Container rescan checkout pinned to v6** — the daily image rescan now uses a v6-pinned `actions/checkout` SHA aligned with the rest of the pipeline.
- **main-ui-smoke boot script** — the standalone container boot script now assembles the `.next/static` tree explicitly (`rm`/`mkdir`/`cp -a`) so a missing source dir no longer aborts the smoke under `set -e`.
- **Frontend contract hygiene** — closed frontend contract gaps surfaced by the post-v0.81.3 audit.
- **Audit contract runtime gaps** — closed runtime gaps in audit-log integrity, signing, and lifecycle posture surfaced by the post-v0.81.3 audit.
- **Adaptive backpressure retry-after jitter** — retry-after now uses multiplicative jitter so colocated callers don't all retry on the same boundary at base ≈ 1s.
- **`scripts/retrigger_stranded_pr.sh` race** — the close→reopen gap now polls the GitHub API until the PR's state is observably `closed` before issuing the reopen call (was a fixed `sleep 2`). Prevents the reopen from racing against propagation and silently no-opping.
- **`release.yml` docs-site invalid `timeout-minutes` on reusable caller** — GitHub Actions rejects `timeout-minutes` on a job whose body is `uses: ./.github/workflows/...`; the field made `release.yml` fail validation on every push to main. Removed the field from the `docs-site` caller and reverted `_is_reusable_caller()` in `scripts/check_workflow_timeouts.py` so the gate skips reusable callers (with a `Why:` comment so the next contributor doesn't re-add the broken field) (#2016).
- **`scripts/run_scale_evidence.py` ValueError on outside-ROOT `--output`** — `args.output.relative_to(ROOT)` raised when the operator passed an absolute path outside the repo. Wrapped in `try/except` with a fallback to the absolute path (#2016).
- **Vulnerability table grouped-view windowing** — the grouped-by-package and grouped-by-source paths in `ui/app/vulns/page.tsx` now cap each group at `PAGE_SIZE` with an overflow notice, matching the flat-mode windowing already in place. Closes the vulns half of #1955 (#2015).

### Security
- **Six missing UI relationship colors + Vitest invariant** — `RELATIONSHIP_COLOR_MAP` in `ui/lib/graph-schema.ts` was missing `REMEDIATES`, `TRIGGERS`, `MANAGES`, `OWNS`, `PART_OF`, `MEMBER_OF`. `MANAGES` was the freshest gap — the cloud_principal → agent edge added in #1996 was rendering without colour. New `ui/tests/graph-schema-color-invariant.test.ts` walks every `RelationshipType` value and fails when any is missing from the colour map (audit-4 #2008).
- **`shutil.which()` → absolute path TOCTOU** — `proxy_sandbox.resolve_container_runtime` and `filesystem._scan_archive` now resolve the binary via `shutil.which` once and pass the absolute path through to `subprocess`, closing the small PATH-substitution window between resolve and exec (audit-4 #2008).
- **`O_NOFOLLOW` on skill-bundle hash read** — `skill_bundles._sha256_file` now opens with `os.O_RDONLY | os.O_NOFOLLOW` so the kernel itself rejects a symlinked leaf, closing the gap between the prior symlink check and the read (audit-4 #2008).
- **Auth attempt counter is clustered-mode visible** — `_check_auth_session_rate_limit` emits a one-shot WARNING log on first use whenever clustered control-plane mode is detected (`AGENT_BOM_POSTGRES_URL` or `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT`), so operators see the cross-replica multiplier on the in-process counter. PR-A introduced the warning (audit-5 PR-A #2010); the Postgres-backed counter that fully closes the gap landed in PR-C #2012 (see entry below).
- **Cluster-safe shared auth state** — auth session attempt counters and revoked session nonces now persist through `agent_bom.api.shared_auth_state`, which auto-selects an `InMemoryAuthState` backend by default and a `PostgresAuthState` backend when `AGENT_BOM_POSTGRES_URL` is set. Closes the cross-replica visibility gap that PR-A only warned on; SQL is parameterised through module-level constants to keep the surface Bandit-clean (audit-5 PR-C #2012).
- **Body-drain middleware slowloris floor** — `MaxBodySizeMiddleware` now enforces a configurable minimum throughput (`AGENT_BOM_BODY_MIN_BPS`, default 256 B/s) on request-body reads so a slow client can no longer hold a worker indefinitely while staying under the size cap (audit-5 PR-C #2012).
- **Auth middleware hardening** — header normalisation, exempt-path startup assertions, and tightened trust-proxy posture across the auth middleware stack.
- **Tenant RLS bypass guard now under test** — the `APIKeyMiddleware` defence-in-depth check that rejects any request still inside an active `bypass_tenant_rls()` context is now covered by two regression tests (`tests/test_api_hardening.py`). Locks the guard so a future refactor cannot quietly drop it.
- **MCP sandbox `image_pin_policy` posture surfaced** — `/v1/auth/policy` now reports the deployment-wide default and recommends `enforce` for production.
- **Cross-parser dedup proofs + Postgres RLS red-team test for `scan_jobs`** — added structural and runtime guards proving a session bound to tenant B cannot read tenant A `scan_jobs` rows under a non-superuser role.
- **Dependabot UI lockfile workflow no longer trusts the PR `scripts.lock:normalize` entry** — replaces the `npm run lock:normalize` step with an inline `npm install --package-lock-only --ignore-scripts` so a Dependabot branch can't redefine the script under a privileged `pull_request_target` token.

### Internal
- **Tracked Finder duplicate artifacts blocked** — CI now refuses to merge tracked macOS Finder duplicate files (e.g. `… 2.md`).
- **Real Postgres integration contract** — `tests/test_postgres_integration.py` now exercises real Postgres for job, audit, and RLS contracts.
- **Stricter mypy on four more API modules** — `agent_bom.api.scim`, `agent_bom.api.storage_schema`, `agent_bom.api.tenant_quota_store`, `agent_bom.api.tracing` now run under the per-module strict overrides (`disallow_untyped_defs`, `disallow_incomplete_defs`, `warn_return_any`, `warn_unused_ignores`). Phase 3 of #1969 (#2003).
- **UI `lib/api.ts` presentation helpers extracted** — `severityColor`, `severityDot`, `formatDate`, `isConfigured` moved to `ui/lib/api-format.ts` and re-exported from `lib/api.ts` so 50+ caller imports keep working unchanged. First step toward the broader decomposition tracked in #1965 (#2004).
- **Pending-digest CI gate now ages markers out at 24h** — `scripts/check_docker_base_policy.py` reads each `# pending-digest` marker's `git blame --porcelain` committer-time and fails when older than `PENDING_DIGEST_MAX_AGE_SECONDS` (default 86400). Stops the marker from quietly outstaying its purpose if dependabot's docker job misses a bump (audit-3 #2005).
- **`/v1/posture/backpressure` explicit `_ROLE_RULES` entry** — narrower entries listed before broad `/v1/posture` for grep/audit clarity. Behaviour unchanged (audit-3 #2005).
- **`_clean_graph_part` fallback chain for `service`** — provider's two-source fallback chain now also applies to service (recovers `<provider>-<service>` segment from `agent_dict.source`); `resource_type` keeps the literal placeholder (audit-3 #2005).
- **README cloud CSP inventory** — README header now enumerates AWS, Azure, GCP, Snowflake, Databricks, CoreWeave, Nebius next to "cloud" (audit-3 #2005).
- **Tenant RLS bypass guard tests** — `APIKeyMiddleware`'s defence-in-depth check that rejects requests entering with `bypass_tenant_rls()` still active is now under regression coverage in `tests/test_api_hardening.py` so a future refactor can't quietly drop the guard (audit-2 #2002).
- **`scripts/retrigger_stranded_pr.sh` close→reopen race** — now polls the GitHub API until the PR's state is observably `closed` before issuing the reopen call (was a fixed `sleep 2`). Prevents the reopen from racing against propagation and silently no-opping (audit-2 #2002).
- **Hermetic Python scanner surfaced in docs** — README and `docs/ARCHITECTURE.md` now name the single-language stack (CLI / FastAPI / MCP / scanners / enrichment / blast / IaC / CIS in one Python interpreter, native dpkg/RPM disk-image parsers, `syft` opt-in tar-archive fallback only) along with the honest tradeoffs (slower at huge fanouts, higher per-package memory) (#2015).
- **mypy strict overrides expanded to nine more modules** — `agent_bom.api.compliance_signing`, `dashboard_csp`, `metrics`, `scim`, `storage_schema`, `tenant_quota_store`, `tracing`, plus `agent_bom.backpressure` and `agent_bom.proxy_sandbox` now run under `disallow_untyped_defs` / `disallow_incomplete_defs` / `warn_return_any` / `warn_unused_ignores`. Phase 3 of #1969 (#2015).
- **`docs.yml` Python pin aligned to 3.11** — the docs-build job now uses the same Python the rest of the workflows do, removing a 3.12 outlier from the matrix.

---

## [0.81.3] – 2026-04-23

### Changed
- **Deployment and runtime guidance** — the README, self-hosted EKS guide, endpoint fleet guide, and proxy-vs-gateway-vs-fleet guide now surface the current graph scale boundary, recommended self-hosted defaults, runtime deployment matrix, and discovery-confidence boundaries where operators actually make rollout decisions.

### Fixed
- **Graph overview regression guardrail** — the graph API test suite now locks the default `/v1/graph` overview path to the store-backed `page_nodes` / `edges_for_node_ids` / `snapshot_stats` flow so filtered paging cannot silently fall back to full `load_graph()` materialization.
- **Docker Hub release sync** — the release workflow now uses a Docker Hub short description that stays under the registry API byte limit, preventing the `Publish to Docker Hub` job from failing after image push.

---

## [0.81.2] – 2026-04-23

### Added
- **UI session and capability contract** — `/v1/auth/me` now exposes authenticated actor, tenant, backend role, UI-facing capability summaries, and explicit `can_see` / `can_do` guidance so the browser shell can reflect the real backend auth model instead of inferring permissions ad hoc.
- **Endpoint enrollment identity contract** — managed endpoint onboarding bundles now emit stable `source_id`, `enrollment_name`, owner, environment, tag, and MDM metadata so fleet inventory can preserve one explicit endpoint identity model across Jamf, Intune, Kandji, and local rollout paths.

### Changed
- **Release-managed version surfaces** — the bump/check scripts now manage compose and runtime version pins as first-class release surfaces so image/version drift fails fast in CI instead of leaking into post-tag cleanup.
- **Snowflake schedule parity** — warehouse-native deployments now persist recurring scan schedules in Snowflake and wire `/v1/schedules*` through the same backend-selection path as jobs, fleet, and gateway policy stores.
- **Snowflake exception parity** — exception workflows now persist through the Snowflake backend too, extending the warehouse-native control-plane boundary without overclaiming full Postgres parity.
- **Snowflake tenant-scoped store lookups** — job, fleet, schedule, and exception lookups/deletes now carry tenant scope into the Snowflake store layer instead of relying only on post-hoc route checks, keeping the warehouse path aligned with the platform’s defense-in-depth tenant model.
- **Graph search and slice filtering** — the control plane now uses indexed graph-node search paths with server-side entity, severity, compliance-prefix, and data-source filters so larger tenant snapshots do not fall back to broad client-side graph scans.
- **Graph overview pagination** — the default `/v1/graph` overview path now pages nodes and page-local edges from the store instead of materializing whole snapshots in memory before pagination.
- **Endpoint onboarding bundles** — managed endpoint rollout bundles now carry a machine-readable enrollment manifest plus optional stable fleet `source_id` wiring so Jamf, Intune, and Kandji pushes can keep one explicit endpoint identity contract instead of only raw install scripts.
- **Deployment and product framing** — README, deployment docs, self-hosted diagrams, trust-boundary docs, and Snowflake-parity guidance now align around `AI supply chain and infrastructure`, one obvious pilot path, one obvious production path, and explicit self-hosted vs MSSP boundaries.
- **MCP server modularization** — the monolith split continued with extracted shared scan pipeline, resource/prompt catalog, FastMCP bootstrap helpers, and runtime catalog tool registration while keeping `create_mcp_server()` behavior and public imports stable.

### Fixed
- **Shield concurrency and API rate limiting** — shield now reuses a bounded async bridge instead of spinning up unbounded executor paths, and the in-memory API rate limiter is explicitly thread-safe.
- **Platform record invariants** — persisted fleet and MCP observation records now normalize tenant identity and UTC ISO-8601 timestamps consistently on read/write so graph, fleet, runtime, and audit correlation work from the same canonical model.
- **Audit and graph query hardening** — exception approval/revocation no longer allow actor spoofing, graph routes move sync store calls off the event loop, SQLite graph search falls back cleanly when FTS `MATCH` expressions error, and audit replay rejects malformed short HMAC values instead of truncating them into a false compare.

### Security
- **Gateway hardening** — scoped API keys are now enforced on the routes that already advertise scoped auth behavior, and gateway 404 responses no longer leak tenant-specific upstream details.
- **Runtime monitor defaults** — the optional monitor DaemonSet now uses a dedicated service-account path, disables automounted service-account tokens, and is documented as an explicit zero-trust, off-by-default runtime surface rather than an assumed deployment requirement.

---

## [0.81.1] – 2026-04-22

### Added
- **Inventory-first MCP visibility** — the control plane now surfaces MCP command/URL, auth mode, credential-backed configuration, fleet timing, and provenance across scans, fleet sync, gateway discovery, and persisted observations instead of forcing operators to infer source context from summary badges.
- **Operator feedback surface** — the shipped UI now includes in-product `Share feedback` and `Report bug` entry points with a copyable support bundle instead of relying on out-of-band issue filing alone.
- **Runtime rollout packaging** — endpoint proxy bundles can now be rendered as `.pkg`, `.msi`, Homebrew, and MDM-oriented rollout assets, and Kubernetes deployments can opt into proxy sidecar auto-injection through the packaged mutating webhook path.

### Changed
- **Self-hosted runtime model clarity** — the product now documents `fleet`, `proxy`, and `gateway` as peer surfaces with explicit deployment/use guidance, tighter EKS rollout docs, clearer entrypoints, and an honest retention/security-lake model that matches the current code and storage backends.
- **Security graph semantics** — the UI and docs now make snapshot identity, scope, timestamps, pagination, node identifiers, and blast-radius semantics explicit so graph investigation scales without inventing a second graph model in the operator workflow.
- **Release-caveat guidance** — graph/load boundaries, screenshot-redaction scope, centralized managed-connection limits, and the contributor workflow around GitHub’s `Update branch` synthetic-head problem are now explicit in the shipped docs instead of living as tribal knowledge.

### Fixed
- **AWS/EKS operator path** — the reference installer now includes preflight checks and post-deploy verification so self-hosted rollout is not "install and guess" anymore.
- **Skill-audit correlation gap** — skill-audit findings now feed the graph instead of landing as an orphan analysis surface outside the main inventory and blast-radius model.
- **Runtime contract coverage** — gateway rate-limit behavior and inbound OCSF normalization now have explicit contract tests instead of relying on indirect coverage only.

### Security
- **Runtime hardening sweep** — middleware RBAC write-route coverage is closed, cached proxy policy bundles are Ed25519-signed and fail closed on mismatch, gateway policies can hot-reload without redeploy, and replay detection now uses a bounded long-window design instead of a short-lived exact-only cache.
- **Deploy-time hardening** — the AWS/EKS rollout path now validates control-plane inputs before install, and packaged runtime operations document policy-signing rotation and cert-manager-backed webhook certificate renewal instead of leaving those as tribal knowledge.

---

## [0.81.0] – 2026-04-21

### Added
- **Hosted control-plane source workflows** — first-class source records and source-linked jobs are now joined by persisted schedule controls on `/sources`, so operators can create recurring runs against real `source_id` records instead of reading static guidance (#1602, #1606).

### Changed
- **Blast-radius scoring semantics** — EPSS percentile tiers now influence blast-radius scoring directly, and the previous 35-point deduction ceiling has been removed so high-reach critical exposure does not flatten into the same score band (#1605).
- **Package lookup hot path** — version parsing is cached and package presence checks are batched, cutting repeated database round-trips on larger scan inventories (#1605).
- **Traceability on hot paths** — the API, graph builder, DB lookup path, and runtime proxy now emit OTEL spans with W3C trace propagation so control-plane and proxy activity share one trace context (#1605).

### Fixed
- **Release-managed surface alignment** — package metadata, Dockerfiles, Helm values, runtime examples, registry manifests, and marketplace-facing version pins now align on `0.81.0` instead of leaving post-release drift for operators to discover manually.

### Security
- **Tenant-scoped control-plane reads** — asset routes now enforce tenant scope directly instead of trusting caller-provided tenant context, closing the highest-risk cross-tenant read gap from the post-release audit (#1603).
- **Fail-closed OIDC and audit integrity** — OIDC discovery now refuses unsafe tenant/JWKS combinations, audit records are chained instead of independently HMACed, and gateway requests validate API keys against control-plane state before relay (#1603).
- **Per-tenant runtime fairness** — scan concurrency and operator policy surfaces now expose tenant-specific quota enforcement instead of relying on one global in-process ceiling (#1605).

---

## [0.80.1] – 2026-04-21

### Fixed
- **Standalone UI image release path** — the Next.js container build now emits the `.next/standalone` output expected by the published `agent-bom-ui` image, and CI smoke-tests that path before release.
- **Version-surface coherence** — Helm examples, runtime sidecar manifests, release verification docs, and product metrics now align on `0.80.1` so the public release surfaces match the shipped tag.

### Security
- **Tenant and gateway auth hardening** — Postgres-backed API key verification can now resolve non-default tenant keys during auth and gateway relay paths, instead of silently falling back to default-tenant visibility under RLS.

---

## [0.80.0] – 2026-04-21

### Added
- **Control-plane auth for the shipped UI** — OIDC, trusted-proxy browser auth, session API-key fallback, and runtime auth introspection now let the dashboard operate as a real operator surface instead of a same-origin-only shell.
- **Hosted-product source registry baseline** — the API and UI now expose first-class source records, source-linked jobs, and persisted schedule state as the first slice of the hosted control-plane model.
- **Signed release surfaces** — Helm OCI publish, UI image release wiring, and stronger release verification/docs were added to the productized deployment path.

### Changed
- **P0/P1 audit closure** — visual leak detector races, timeout audit gaps, resolver/VEX strictness, ServiceMonitor/operator defaults, CSP documentation, and UI dependency/release guardrails were tightened across the release lane.
- **Deployment docs and diagrams** — self-hosted operator guidance, EKS rollout docs, and enterprise topology explanations were rewritten to match the actual control-plane/runtime split in code.

### Fixed
- **Gateway and runtime audit integrity** — timeout paths now audit correctly, OCR runs once per response instead of once per image block, and the control plane/runtime surfaces agree on the operator deployment contract.
- **UI packaging accuracy** — README and deployment copy now describe the Python image and standalone UI image honestly instead of implying a single bundled live dashboard path.

---

## [0.79.0] – 2026-04-20

### Added
- **Multi-MCP gateway and rollout path** — central `agent-bom gateway serve`, fleet-driven upstream discovery, focused EKS pilot guidance, and deployment-first docs for self-hosted operator environments (#1551, #1552, #1554, #1555, #1560).
- **Visual leak runtime enforcement** — `VisualLeakDetector` is now wired into gateway and proxy protection paths so screenshot and image tool responses can be redacted or blocked as part of the runtime policy surface (#1572, #1575).
- **Bidirectional OTEL product surface** — OTLP export, W3C trace context, `/v1/traces` ingest, and runtime OTEL evidence are now called out as first-class operator capabilities in the shipped product surfaces (#1583).

### Changed
- **Tenant-native persistence and parity** — fleet, policy, audit, baseline, trends, analytics, and Snowflake/Postgres-backed stores now query natively by tenant rather than relying on broad reads plus in-memory filtering (#1558, #1559, #1561, #1562, #1567, #1569).
- **RBAC and control-plane hardening** — enterprise/compliance/auth-policy surfaces align on the current `admin` / `analyst` / `viewer` model with route-level and middleware-level enforcement kept in sync (#1576).
- **Monolith reduction in core surfaces** — `mcp_server`, `ast_analyzer`, Postgres stores, and console output were split into focused modules while preserving CLI/API behavior and published contracts (#1561, #1564, #1565, #1566).

### Fixed
- **Graph blast-radius hot path** — vuln-to-server edge resolution now uses indexed lookups instead of the prior nested agent×server cross-product in the graph builder (#1581).
- **HTTP retry behavior under load** — outbound retry backoff now adds positive jitter so concurrent OSV and HTTP clients do not back off in lockstep (#1582).
- **Tenant-blind enterprise reads** — baseline compare, trends, audit export, and related enterprise/operator surfaces now honor tenant scope consistently across backends (#1559, #1569).
- **Write-route audit coverage** — exception deletion, SIEM test, schedule mutation, fleet sync/state updates, and related operator write paths now emit audit entries with actor and tenant context.
- **Ignore-file error handling** — malformed YAML/JSON ignore files now fail through narrow parse errors instead of broad exception swallowing (#1582).

### Security
- **Hardened audit evidence chain** — audit HMAC coverage now includes payload `details`, routes fetch tenant-scoped audit entries at the store layer, and exported evidence stays tamper-evident across backends (#1559).
- **Transport and operator posture clarified** — HTTPS-external / trusted-boundary-internal deployment guidance, OTEL/OPA positioning, and current auth/RBAC behavior now match the live product and deployment docs (#1583).

### Docs
- **Release and deployment alignment** — README, Docker Hub README, product brief, EKS guidance, backend matrix, and release-managed version surfaces are aligned on `0.79.0`.

---

## [0.77.1] – 2026-04-18

### Fixed
- **Release metadata alignment** (#1498) — corrected 0.77.0 follow-up: brought `pyproject.toml`, `uv.lock`, and integration listings to a consistent 0.77.1 after an intermediate packaging drift

---

## [0.77.0] – 2026-04-18

### Added
- **Live Kubernetes posture scanning** (#1489) — cluster-scoped scan path walks live API-server objects, correlates pod specs with image/CVE inventory, and emits findings through the unified pipeline
- **Control-plane enterprise auth** — SAML SSO assertion exchange (#1487), API key rotation policy with audit trail (#1492), tenant quotas (#1486), and tenant-scoped rate limiting with Postgres tuning (#1493)
- **Proxy & fleet durability** — idempotent fleet/proxy ingest (#1473), circuit breaker + DLQ for proxy audit delivery (#1494), service-mesh + policy-controller templates for EKS (#1495)
- **Helm packaging for the control plane** (#1453) — end-to-end Helm chart with production operator defaults (#1458), operator observability + backups (#1472), encrypted backup restore path (#1485)
- **MCP agent mesh surface** — agent context graph with lateral movement analysis, IaC findings stitched into the unified graph (#1426), programmable graph query traversal (#1427), mesh cleanup polish (#1470)
- **Findings as first-class UI surface** (#1423) — unified, deep-linkable findings view across vulnerability, policy, and compliance sources with one-click drill into the security graph (#1395, #1397, #1399, #1400, #1401)
- **Snowflake CIS password policy coverage** (#1429) and Snowflake storage backend parity (#1408)
- **Live UI configurability** — runtime-configurable API endpoint (#1452), dashboard posture card unification (#1447), theme support across dashboard and graph surfaces (#1404, #1407, #1411, #1413)
- **Data-sources product surface** (#1421), how-agent-bom-works explainer (#1440), and deployment/hosting guidance (#1444)

### Changed
- **AST analyzer modularization** — JS/TS (#1424), Go (#1425), and shared models (#1420) extracted into focused helpers; SAST helper-chain findings reframed for clearer attribution (#1488)
- **MCP server modularization** — specialized tool registrations (#1439) and runtime helpers (#1438) split out of the main server module
- **Scanner modularization** — OSV helpers (#1418), runtime state helpers (#1417), risk/blast-radius helpers (#1416) split into dedicated modules
- **CLI modularization** — option groups split into helper modules (#1434); wayfinding and doctor output polished (#1394)
- **Proxy policy & audit split** (#1436) for cleaner policy boundaries
- **Remediation scoring anchored to blast-radius risk** (#1443), not CVSS alone
- **Prompt-injection analyzer signals tightened** (#1490)
- **Analytics ingest batched** for flagged trace events (#1428)

### Fixed
- **Operator drilldown UX** (#1496), pilot UI reliability (#1471), mesh UI cleanup + README visuals (#1470)
- **Pilot rate limiting + control-plane HA hardening** (#1460), pilot hardening follow-ups (#1457), pilot auth + endpoint fleet path (#1456)

### Security
- **Gateway policy RBAC hardened** (#1451)
- **Marketplace publishing surfaces hardened** (#1442)
- **Supply-chain trust + extras audit made explicit** (#1441)
- **UI dependency + validation contract hardened** (#1446)

### Docs
- **Enterprise scale guidance + benchmark harness published** (#1459)
- **Data ingestion + security model documented** (#1437)
- **Docs rebuilt on release tags** (#1419)
- **Sidebar IA clarified** (#1412), scan page product surfaces clarified (#1415)

### Infra
- **mypy phase 2 body checking enabled** (#1433)
- **Cloud normalization coverage with fixtures** (#1410)
- **Storage backend contract exposed on health** (#1409)
- **Backend parity + Snowflake modes documented** (#1408)

---

## [0.76.4] – 2026-04-13

### Added
- **Release-surface refresh** — README, PyPI, and Docker Hub now show the current product path with real screenshots, tightened copy, clearer architecture/graph visuals, and a shorter demo flow
- **CVE and graph drilldowns** — vulnerability rows and graph detail panels now provide richer fix, impact, compliance, and evidence context instead of acting like dead text

### Changed
- **Summary-first loading** — dashboard, jobs, activity, vulnerabilities, mesh, context, and insights now unlock from lightweight job summaries first and only hydrate deeper scan data when the active panel needs it
- **Graph defaults and fallbacks** — focused graph views, empty states, findings fallbacks, and posture labels now favor scoped, readable investigation paths over dumping full topology state at once
- **Docker freshness operations** — release automation now includes an explicit Docker `latest` refresh path so base-image fixes can be rebuilt and republished without waiting for a feature release

### Fixed
- **Snowflake SQL hardening** — notebook identifier quoting and `days` coercion now validate and escape values before SQL interpolation
- **Jobs summary contract** — pushed and completed scan rows now keep `completed_at`, `error`, and summary metadata aligned across API, dashboard, and jobs surfaces
- **App-router release build stability** — release pages that rely on search params now render safely under `Suspense`, fixing the current Next.js app-router build path
- **AST/SAST depth wave** — validator-aware guards, transformed-return sanitizers, JS/TS early exits, and cross-file helper modeling reduce false positives while improving Python, JS/TS, and Go parity

### Security
- **Container rebuild response** — Docker refresh and rescan wiring now close the loop for newly published Alpine fixes instead of relying on manual Docker Hub inspection
- **Snowflake query validation** — user-controlled notebook and date inputs are now coerced or quoted before execution, removing the identified injection and query-shape risks

---

## [0.76.2] – 2026-04-09

### Changed
- **Patch release alignment** — managed release/version surfaces are now aligned on `0.76.2` for the next patch cut

### Fixed
- **Alpine package visibility** — local vulnerability DB sync now ingests Alpine secdb in addition to OSV, so Alpine package advisories like the recent `openssl` and `util-linux` fixes are detected without waiting on OSV lag
- **Alpine scanner coverage** — Alpine OS-package fallback queries now include `v3.23`, matching the current container base branch
- **Container hardening** — the Docker build now upgrades installed Alpine packages during both builder and runtime stages instead of only bumping `zlib`
- **Release image gating** — CI and release image scans now fail on fixable `MEDIUM+` and `UNKNOWN` image vulnerabilities while ignoring upstream-unfixed image findings

### Security
- **Container CVE response** — the patch release closes the fixable Alpine `openssl` and `util-linux` image findings and adds stronger pre-release guardrails to stop similar Docker regressions from shipping unnoticed

---

## [0.76.1] – 2026-04-09

### Added
- **CLI output parity for reporting commands** — `check`, `report diff`, and `report history` now have clearer machine-readable behavior, and reporting surfaces that were still missing `--quiet` now support quiet scripting flows
- **CLI troubleshooting coverage** — the shipped docs now include a dedicated debug guide for quiet mode, stdout vs file output, discovery triage, and verification workflows

### Changed
- **Patch release alignment** — release-managed files, Docker/Helm metadata, OpenClaw skills metadata, docs, registry surfaces, and action examples are now aligned on `0.76.1`
- **Verification status wording** — package provenance verification now distinguishes missing attestations from service unavailability instead of collapsing both into a generic unknown state

### Fixed
- **Quiet mode consistency** — reporting and analysis commands now suppress headings/export chatter when `--quiet` is requested
- **Verify JSON output** — `agent-bom verify --json` no longer prepends human console banners before the JSON payload
- **Graph contributor install contract** — graph centrality dependencies and contributor install paths were aligned so graph analysis works in a clean optional-extra install
- **Live MITRE/STIX parsing** — ATT&CK/CAPEC runtime parsing now handles the current upstream payload shape and restores live CWE→ATT&CK mapping
- **Docker Hub release hardening** — release sync, cleanup retention, and version-alignment checks now match the real Docker tag contract and fail loudly on drift
- **Release bump automation** — stale version-bump patterns were removed so dry-run and check mode only flag real managed release surfaces

### Security
- **Supply-chain verification clarity** — provenance verification now reports whether attestations are absent or temporarily unavailable, reducing ambiguous release-audit results for package verification

---

## [0.76.0] – 2026-04-09

### Added
- **Unified graph product path** — persisted snapshots, current-state and diff views, attack-path drilldown, search, impact, delta alert delivery, and Postgres-backed graph persistence are now part of the shipped CLI/API/dashboard flow
- **Multi-language AST/SAST depth** — Python, JS/TS, and Go analysis now include stronger cross-file and taint-aware coverage, plus SARIF import and cleaner custom-rule handling
- **Container layer attribution** — image findings now retain per-layer package provenance so output can show which layer introduced a vulnerable package
- **PDF report export** — `agent-bom scan -f pdf -o report.pdf` now renders the existing HTML report through an optional WeasyPrint-backed export path

### Changed
- **README and architecture visuals** — product positioning, hero commands, and architecture diagrams were shortened and tightened to match the current shipped path without overflowing cards or stale counts
- **Demo CLI polish** — demo and offline copy are shorter, and the scan path no longer prints redundant inner vulnerability banners when the outer progress bar is already rendering the step
- **Release-managed versioning** — docs, deployment files, Helm, OpenClaw, registry metadata, and action examples now align on `0.76.0`

### Fixed
- **Graph correctness and scale** — snapshot isolation, tenant propagation, search escaping, delta dispatch semantics, and direction-aware traversal/reporting were hardened across the recent graph lane
- **Scanner concurrency** — shared cache and scanner-global thread-safety issues were fixed and regression-tested
- **Container evidence depth** — package metadata now tracks layer/package occurrences instead of flattening away provenance
- **Release automation drift** — CodeQL SARIF upload is on v4 and no longer fails when a SARIF file was not actually produced

### Security
- **Release dependency refresh** — cryptography was bumped to `46.0.7`, clearing the active moderate buffer-overflow advisory on the locked release path
- **Graph delta delivery** — delta alerts now flow through the existing dispatcher/webhook surfaces instead of only being computed/export-ready

---

## [0.75.15] – 2026-04-04

### Added
- **API distributed tracing** — request-level `traceparent` propagation, `X-Trace-ID` headers, OTLP/HTTP export, and collector/reverse-proxy contract docs
- **Postgres-backed API rate limiting** — shared throttle state across replicas via `api_rate_limits`, keeping `429` and `Retry-After` semantics consistent
- **Skills AST-aware analysis** — fenced Python and JS/TS code blocks in skill/instruction files now get semantic risk detection for dynamic execution, shell/process execution, and file mutation
- **Skills output schemas** — `skills scan` and `skills rescan` now ship explicit versioned JSON schemas for stable downstream consumption
- **Helm monitoring surfaces** — readiness/startup probes, optional metrics service, optional `ServiceMonitor`, and runtime `/metrics` wiring for Prometheus-friendly deployments
- **Postgres enterprise persistence** — audit log and trend history now have Postgres backends with tenant-aware persistence

### Changed
- **Demo wording** — the built-in `--demo` path is now presented as a curated sample agent + MCP environment, while real local/project scans remain the primary product story
- **Tenant isolation posture** — enterprise stores, gateway policy surfaces, audit/trend history, and shared rate-limit state now align under the same tenant-boundary model
- **Security automation** — daily preventive workflows, deployment freshness checks, and authenticated Railway verification now better reflect real release state

### Fixed
- **GitHub Action enterprise networking** — proxy and custom-CA environment variables now pass through consistently during install and scan steps
- **OpenClaw packaging metadata** — stale skills test-count references were updated to current repo reality
- **Postgres schema drift** — schema summaries, RLS coverage assertions, and table counts now match the current tenant-bearing model

### Security
- **Postgres RLS completion** — all tenant-bearing Postgres tables now enforce row-level security, with shared caches and infra-only tables explicitly excluded from that boundary
- **Enterprise auth maturity** — RBAC route enforcement, OIDC tenant-claim scoping, authenticated request tracing, and shared rate-limiting now operate together as the production API contract

---

## [0.75.14] – 2026-04-03

### Added
- **Next.js Insights page** (`/insights`) — SupplyChainTreemap, BlastRadiusRadial, PipelineFlow, EpssVsCvssChart, VulnTrendChart wired to real scan data; treemap cells are clickable and drill down to `/vulns`
- **Gateway enforcement chart** — audit tab shows stacked bar of blocked/alerted/allowed actions per tool
- **Governance findings chart** — stacked bar of finding severity by governance category
- **Activity query chart** — bar chart of agent query pattern frequency
- **Fleet lifecycle chart** — bar chart of agents by lifecycle state
- **Jobs status donut** — pie chart summarising job queue by status
- **`ui/components/empty-state.tsx`** — reusable `EmptyState` + `ErrorBanner` components used across pages
- **Retry buttons** — Activity and Governance error states now include a Retry button
- **SECURITY.md** expanded — response SLA, known limitations, API security model, disclosure timeline
- **PR template** — added Related Issues, TypeScript check, breaking changes, checklist sections
- **pre-commit hooks** — added `check-yaml`, `check-json`, `check-toml`, `end-of-file-fixer`, `trailing-whitespace`, `detect-private-key`, `check-merge-conflict`, `mixed-line-ending`
- **`agent-bom mcp scan`** — focused MCP server package audit path for pre-install checks
- **Compliance narrative CLI** — auditor-facing narrative export from saved scan reports via `agent-bom report compliance-narrative`
- **MCP caller governance** — per-caller rate limiting, request tracing, and richer tool metrics now flow through the MCP server metrics surface
- **Remote MCP startup contract** — Railway/remote deployments now use an explicit bearer-token contract instead of accidental anonymous exposure

### Fixed
- **JSON report import** — file upload now validates size (10 MB), schema, prototype-pollution keys, and finite numeric values before use (`ui/lib/validators.ts`)
- **`generated_at` TypeScript error** — `ScanResult` does not have `generated_at`; use `scan_timestamp` instead
- **JetBrains claim** — removed from active integrations; filed as issue #412 for proper implementation
- **`skills scan` path handling** — bundle identity now supports referenced files outside the primary file directory, fixing repo-local scans against shared security assets
- **`check` ecosystem ambiguity** — pre-install checks now fail closed on genuinely ambiguous package names and use version-aware registry detection to avoid cross-registry false positives
- **`skills scan --verbose`** — added parity with other CLI surfaces for easier debugging
- **Runtime CLI warning noise** — async proxy tests now use async-aware mocks, removing unawaited coroutine warnings from that path
- **Frontend/backend scan contracts** — UI API types now model `scan_performance`, richer `scorecard_summary`, `posture_scorecard`, and remediation metadata consistently with backend JSON output
- **GitHub Action execution contract** — hardened argv handling, severity validation, pip caching, step summaries, and sanitized PR comment/report generation now match the documented Action behavior
- **Runtime image provenance** — runtime Docker image now builds from repo source instead of reinstalling from PyPI, aligning image behavior with source and release verification
- **MCP execution envelope** — sync and async tools now share bounded concurrency, timeout, metrics, path safety, and sanitized error handling
- **Snowpark enterprise networking** — Snowpark image now supports enterprise proxy and custom-CA configuration like the other maintained image families

### Security
- **JSON file upload** — `ui/lib/validators.ts` guards against DoS via oversized files, prototype pollution, and schema-invalid payloads (no new npm dependencies)
- **API and remote MCP fail closed** — non-loopback API and remote MCP transports now refuse to start without explicit auth unless an insecure override is deliberately supplied
- **Dependency security refresh** — LiteLLM was bumped to `1.83.0`, clearing the active 2026 GitHub security advisories on `main`

---

## [0.75.13] – 2026-04-01

### Added
- **Focused MCP server review** — `agent-bom mcp scan <server>` adds a narrower audit path for a single MCP server or command before adoption
- **Compliance narrative CLI** — compliance narrative export is now reachable from the CLI for release and audit workflows

### Changed
- **Release surfaces aligned** — README, PyPI, Docker Hub, site docs, Helm, OCI metadata, and publishing surfaces now share the same product description and release references
- **Canonical product story** — product positioning, Claude/Cortex integration references, and repo-derived metrics now point back to the canonical brief and generated metrics appendix
- **First-run guidance** — empty-state discovery help now shows concrete Claude, Cursor, Codex CLI, and Cortex CoCo config paths instead of circular retry suggestions
- **SARIF defaults** — SARIF export now auto-enables enrichment when online so severity context lands in GitHub and downstream scanners by default

### Fixed
- **Offline safety boundary** — offline scans now fail closed when the local vulnerability database is missing or incomplete instead of producing a false clean result
- **Incomplete result visibility** — critical scanner and enrichment failures now surface warning summaries instead of silently degrading to partial output
- **Skills scanning** — `agent-bom skills scan .` no longer crashes on repo-local path validation, and the command now supports `-v` / `--verbose`
- **Package checks** — `agent-bom check` now resolves ambiguous package names more safely and avoids cross-ecosystem false positives
- **Output format handling** — unknown output extensions now fail loudly instead of silently falling back to JSON
- **ClickHouse query hardening** — analytics escaping was tightened and the associated tests expanded
- **Release quality gates** — follow-up CodeQL, lint, mypy, FastAPI response-model, and regression issues from the stabilization lane were fixed before release

### Security
- The `0.75.13` release closes the remaining pre-release P0/P1 safety issues from the final audit lane, including offline false-clean behavior, incomplete scan signaling, and ClickHouse query hardening

---

## [0.75.12] – 2026-03-29

### Added
- **First-class skills scanning** — `agent-bom skills scan` and `agent-bom skills verify` are now top-level CLI surfaces for instruction-file trust, provenance, and findings
- **Live MCP tool capability scoring** — added capability-based tool/server risk assessment from `tools/list` introspection, surfaced through MCP and scan outputs
- **Release demo refresh** — updated hero demo and release surfaces for `v0.75.12`

### Changed
- **MCP tool surface** — docs and public surfaces now reflect the current 36-tool MCP server accurately
- **Quickstart alignment** — CLI/docs/demo flows now point to the grouped first-class commands (`agents`, `skills`, `image`, `iac`)
- **Advisory labeling** — unscored vulnerabilities are presented as advisories/pending severity instead of ambiguous unknowns
- **Resolver continuity** — npm version resolution now prefers cached/bundled continuity under rate limiting instead of repeated blocking retries
- **Supply-chain enrichment** — `--enrich` resolves package source metadata before OpenSSF Scorecard lookup and reports explicit enrichment coverage state

### Fixed
- **Blast radius serialization** — package name/version/stable ID now propagate correctly in filesystem and JSON outputs
- **Filesystem posture credibility** — fs/project scans no longer get penalized for missing MCP-only config context; posture and framework mapping now reflect the actual scan mode
- **Framework tagging** — intrinsic vulnerability findings now carry framework tags in both agents and fs modes
- **Remediation output** — remediation JSON now includes populated priority and action fields
- **UI dependency hygiene** — aligned UI eslint peer range with Next.js-supported versions to remove install drift
- **Scorecard source resolution** — npm/PyPI direct dependencies now fall back to source metadata resolution paths so repo URLs, homepages, and Scorecard repos populate end to end

### Security
- No new release-blocking regressions introduced across the `0.75.12` stabilization lane; focused regression suites, UI tests, build checks, and release consistency checks remained green

---

## [0.75.0] – 2026-03-23

### Added
- **Dashboard UX** — posture grade (A-F) hero, top 5 attack path cards, security graph page with interactive React Flow, insight layer toggle (risk/credentials/default), 14-framework compliance heatmap
- **Remediation page** — priority table sorted by blast radius impact, Jira ticket creation per finding, compliance impact summary, severity/framework filters, JSON export
- **Compliance narratives** — `GET /v1/compliance/narrative` generates review-ready text per framework with control-level detail and remediation-compliance bridge
- **`--posture` flag** — 5-line workstation posture summary for solo developers
- **`--fixable-only` flag** — show only vulnerabilities with available fixes
- **`agent-bom doctor`** — preflight diagnostic (Python, DB, network, Docker, MCP configs, API keys)
- **Cross-agent behavioral detection** — `CrossAgentCorrelator` detects lateral movement (3+ agents same tool in 5min), anomaly baseline per agent
- **SSE proxy transport** — `agent-bom proxy --url` for remote SSE/HTTP MCP servers
- **SBOM multi-hop graph** — dependency depth tracking (A→B→C) + CycloneDX `vulnerabilities[]` ingest
- **API rate-limit headers** — `X-RateLimit-Limit/Remaining/Reset` on all responses, `X-API-Version: v1`
- **Jira API endpoint** — `POST /v1/findings/jira` with ephemeral credentials, SSRF-validated
- **False positive feedback** — `POST/GET/DELETE /v1/findings/false-positive` with tenant-scoped persistence
- **Break-glass endpoint** — `POST /v1/shield/break-glass` with admin RBAC + audit logging
- **Prometheus `/metrics`** — fleet_total and fleet_quarantined gauges
- **75 UI component tests** (Vitest + @testing-library/react)
- **8 intent-based OpenClaw skills** — discover, scan, scan-infra, enforce, comply, monitor, analyze, troubleshoot
- **CONTRIBUTING.md** — contributor onboarding guide
- **Enterprise Deployment guide** — MDM push, fleet API, zero-credential architecture

### Changed
- **Homepage reworked** — posture grade + blast radius chains at top, stats compressed to one row
- **Compliance page** — now shows all 14 frameworks (was 6)
- **Security graph** — uses pre-computed blast_radius scores (risk_score, is_kev, epss_score)
- **All dashboard pages** — consistent Loader2 spinners, overflow-x-auto tables, confirmation dialogs on destructive actions, Snowflake-only banners in error state
- **Vulns page** — pagination (50/page), search, FP feedback button, confidence scores
- **Jobs page** — status filter tabs, search, pagination (25/page), JSON export
- **Fleet page** — search, JSON export, confirmation on state transitions
- **Agents page** — search by name
- **CLI output** — severity text labels alongside colors (accessibility)
- **CycloneDX** — `formulation` field identifies agent-bom as generator
- **GitHub Action** — `exclude-unfixable` input for CI gating
- **Architecture diagram** — compact horizontal layout (LR)
- **Count alignment** — release surfaces were brought back to a single source of truth for that release's framework, rule, pattern, page, tool, and format totals

### Fixed
- **Full-stack alignment** — `severity_source`, `confidence`, `nist_800_53_tags`, `fedramp_tags`, `automation_settings`, `vector_db_scan`, `gpu_infra` now serialized in JSON output (were silently dropped)
- **Compliance router** — `/v1/compliance/narrative` no longer shadowed by `/{framework}` wildcard
- **UI field names** — `risk_score ?? blast_score`, `summary ?? description`, `is_kev ?? cisa_kev` with backward compat
- **Offline mode strict** — no silent network fallback when `--offline` set
- **AST prompt detector** — `description`, `help`, `title` fields no longer misclassified as system prompts
- **CodeQL SSRF** — defense-in-depth `validate_url()` at transport layer
- **HSTS header** — `Strict-Transport-Security` added to all API responses
- **OIDC SSRF** — `validate_url()` on discovery URL
- **ECS/EKS test mocks** — updated to paginator pattern
- **Protection engine** — `stop()` persists cleared kill-switch state, semaphore cache bounded to 8 entries
- **Chain-hashed audit log** — each entry includes previous entry's HMAC for tamper-evidence
- **Multi-tenancy isolation** — tenant_id enforced at middleware level
- **Quarantine enforcement** — quarantined agents excluded from fleet list by default
- **Log file permissions** — 0o600 on audit DB, fleet DB, log files
- **Node.js 20 deprecation** — `FORCE_JAVASCRIPT_ACTIONS_TO_NODE24` on dependency-review
- **Local fonts** — Inter + JetBrains Mono bundled (no Google Fonts network dependency)

### Security
- 10/10 OWASP web categories PROTECTED (verified by code audit)
- SLSA L3 provenance on releases, Sigstore signing on PyPI
- 91 SHA-pinned GitHub Actions, 0 npm/Python vulnerabilities
- scrypt KDF for API keys, HMAC constant-time comparison, parameterized SQL everywhere

## [0.74.1] – 2026-03-22

### Security
- **Runtime**: Fix threat level comparison — `ThreatLevel` enum uses ordinal comparison; previously `CRITICAL > HIGH` was `False` (lexicographic), so escalations were never detected
- **Runtime**: Per-session shield engine isolation — zero trust, no cross-session threat contamination
- **Runtime**: Rate limiter now blocks (HIGH/CRITICAL severity) instead of alert-only (MEDIUM)
- **Runtime**: HTTP protection server auth via `AGENT_BOM_PROTECTION_API_KEY` with constant-time comparison
- **Runtime**: Single zero-width space now detected (was requiring 3+ consecutive chars, bypass fixed)
- **Runtime**: Unicode path traversal (`\u002e\u002e`) detection added
- **Runtime**: 3 new credential patterns (HashiCorp Vault, AWS session tokens, PagerDuty) — 112 total
- **Runtime**: Drift baseline persisted to disk, survives engine restarts in shield mode
- **Supply chain**: Go module provenance verification via sum.golang.org checksum database
- **Supply chain**: Provenance results persisted in Package model (integrity_verified, provenance_attested)

### Fixed
- **Compliance**: Wire NIST 800-53 Rev 5 tags in scanner pipeline (was defined but never called)
- **Compliance**: Wire FedRAMP Moderate baseline tags in scanner pipeline
- **Policy**: Add 9 missing framework tag fields to policy engine expressions (all 14 frameworks now accessible)
- **Scanner**: Surface non-OSV ecosystem skips to users with per-ecosystem breakdown
- **Scanner**: Track per-package CVE lookup errors and report at scan completion
- **Scanner**: Add severity_source field for audit trail (cvss, osv_database, ghsa_heuristic)
- **Scanner**: Bound semaphore cache to 8 entries (prevents memory leak in long-running API servers)
- **Scanner**: Kill-switch state now persisted on stop() (was leaving stale blocked state on disk)
- **Cloud**: ECS/EKS/SageMaker discovery uses boto3 paginators (was missing results beyond page 1)
- **MITRE ATLAS**: Expanded from 8 to 30+ technique mappings across all tactic categories

### Added
- `make dev` — starts API server + Next.js dashboard in parallel
- `make install-all` — installs all development extras (dev + ui + mcp-server)
- `dev-all` extra in pyproject.toml for one-command setup
- `AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT` config (default 45s)
- Portable `.claude/launch.json` for dev server configs
- Mermaid blast radius diagram in README
- Mermaid architecture diagram in README
- Compliance frameworks table in README

### Changed
- README: ecosystem count 11 → 15, credential patterns 31 → 34, compliance frameworks 14 → 16
- MITRE ATLAS coverage documented accurately (30+ observable techniques)

---

## [0.74.0] – 2026-03-21

### Dashboard & HTML Report

- **Sidebar navigation** — collapsible left sidebar replaces top nav across Next.js dashboard (18 pages) and HTML report, with 5 grouped sections, command palette (Cmd+K), active link highlighting, mobile drawer (#993)
- **React Flow edge fix** — topology graph nodes now connect properly with Handle components, eliminating all "null handle id" errors (#993)
- **Topology enhancements** — nodes show server count, vuln count, credential indicators; animated edges for vulnerable connections; zoom controls; empty state (#993)
- **HTML report sidebar** — fixed 220px sidebar with IntersectionObserver active section tracking, mobile responsive hamburger toggle, print-friendly layout (#993)

### Security

- **Dependency CVE fixes** — pillow ≥12.1.1 (CVE-2026-25990 PSD OOB write), protobuf ≥6.33.5 (CVE-2026-0994 ParseDict DoS), pyjwt ≥2.12.0 (CVE-2026-32597 crit header bypass), tornado ≥6.5.5 (CVE-2026-31958 multipart DoS, GHSA-78cv-mqj4-43f7 cookie injection)
- **CI/CD hardening** — all GitHub Actions pinned to SHA digests, no `@master` refs, scoped permissions

### Fixed

- **Dashboard layout** — wider content area (1400px), CSS page transitions, thin scrollbar, card hover effects
- **HTML report unused variables** — removed dead nav link variables (ruff F841)

---

## [0.73.0] – 2026-03-19

### Architecture

- **5-product CLI** — `agent-bom`, `agent-shield`, `agent-cloud`, `agent-iac`, `agent-claw` — one package, five entry points, zero duplication (#967)
  - `agent-bom` — BOM generation + vulnerability scanning
  - `agent-shield` — runtime protection (proxy, protect, guard, watch, audit)
  - `agent-cloud` — cloud infrastructure (aws, azure, gcp, snowflake, databricks, huggingface, ollama, posture)
  - `agent-iac` — IaC security (scan, policy, validate)
  - `agent-claw` — fleet governance (fleet, serve, api, schedule, report, connectors)
- **Shared entry point factory** (`_entry.py`) — consistent error handling + update check across all 5 products
- **Parameterized help categories** — each product shows relevant command groups in `--help`
- **Full backward compat** — `agent-bom runtime proxy`, `agent-bom cloud aws`, etc. still work

### Added

- **CycloneDX 1.6 ML BOM extensions** — native `modelCard`, `data` components, `machine-learning-model` type with `quantitativeAnalysis` for training metrics (#967)
- **Agent-shield deep defense mode** (`--shield`) — correlated multi-detector threat scoring, `ThreatLevel` escalation (NORMAL→ELEVATED→HIGH→CRITICAL), automatic kill-switch on CRITICAL (#967)
- **Graph-native AIBOM export** — `to_graphml()` for yEd/Gephi/NetworkX, `to_cypher()` for Neo4j with AIBOM node labels (AIAgent, MCPServer, Package, Vulnerability) (#967)
- **CLI graph formats** — `agent-bom graph --format graphml|cypher` alongside existing json/dot/mermaid (#968)
- **CLI shield flags** — `agent-shield protect --shield --correlation-window 30` (#968)
- **API: graph export** — `GET /v1/scan/{job_id}/graph-export?format=graphml|cypher|dot|mermaid|json` (#970)
- **API: shield control** — `POST /v1/shield/start`, `GET /v1/shield/status`, `POST /v1/shield/unblock` (#970)
- **MCP graph tool** — `graph_export` MCP tool for graphml/cypher/dot/mermaid from scan results (#972)
- **agent-cloud new commands** — `snowflake`, `databricks`, `huggingface`, `ollama`, `posture` (#967)
- **agent-claw fleet** — `fleet sync|list|stats` commands + `connectors` command (#967)

### Fixed

- **Fleet min_trust Python 3.14** — explicit `float()` coercion + defensive `(trust_score or 0.0)` (#969)
- **API test noise** — mock `_run_scan_sync` with pytest `monkeypatch` fixture scoped to test file only (#970)
- **flatted 3.4.1→3.4.2** — GHSA-rf6f-7fwh-wjgh prototype pollution in `/ui` (#970)
- **CVE-2026-33231 suppression** — nltk wordnet_app remote shutdown (not reachable — never imported) (#971)
- **Stale test name** — `test_total_agent_types_is_18` → `is_31` (#967)

---

## [0.72.0] – 2026-03-19

### Added

- **30 MCP clients** — added Pieces, mcp-cli, Trae, Aide, Void, Replit Agent, Aider, Sourcegraph Cody, Tabnine, Copilot CLI, Junie, JetBrains AI
- **AI BOM tools** — 32 MCP tools for scanning, compliance, runtime, cloud in the `0.72.0` release
- **Version accuracy** — all surfaces updated with correct version and client counts
- **Compliance noise reduction** — actionable findings only in default output

---

## [0.71.4] – 2026-03-18

### Fixed
- **SARIF output**: paths were absolute (`/Users/.../Agent-Bom`) causing GitHub Security tab to show "No summary of scanned files". Now relative paths pointing to manifest files (#945)
- **Scanner accuracy**: git commit SHAs in `fixed_version` from OSV data no longer generate false positive "assuming affected" warnings — silently skipped as non-version data (#946)
- **Docker pip CVEs**: upgraded pip in all 6 Docker images — fixes CVE-2025-8869 (5.9M) and CVE-2026-1703 (2.0L) (#947)
- **Release pipeline**: self-scan gate now blocks ALL publish jobs (PyPI, Docker, GHCR, Sigstore, SLSA). No release ships with HIGH+ CVEs (#944)
- **Self-scan noise**: post-merge scan now only uploads HIGH+ findings to GitHub Security tab (was uploading all severities, flooding with 78 low-severity base-image CVEs) (#945)

## [0.71.3] – 2026-03-18

### Fixed
- **Scanner accuracy**: empty string versions no longer silently bypass OSV queries — now logged as unresolvable (#933)
- **HTTP reliability**: all 19 `urllib.request.urlopen` callers migrated to httpx with exponential backoff, Retry-After handling, and configurable timeouts (#878, #932)
- **Context graph OOM**: BFS queue bounded at 10,000 entries + O(1) cycle check via frozenset to prevent memory explosion on dense deployments (#877, #930)
- **Docker Hub token leak**: `release.yml` now masks API token with `::add-mask::`, validates before use (#929)
- **CI self-scan gap**: added `agent-bom scan --os-packages` inside built Docker image to catch base-image CVEs (glibc, sqlite3, dpkg) that Docker Hub found but CI missed (#931)
- **Alpine CI image**: pinned `python:3.12-alpine` by SHA256 digest (#929)
- **Glama Dockerfile**: added missing HEALTHCHECK (#929)
- **Container rescan**: weekly container image rescan escalated from informational to exit-code 1 with warning annotation (#931)
- **action.yml**: shortened description to 91 chars (was 141, GitHub Marketplace truncates at 125) (#933)

### Added
- **CMMC 2.0 in REST API**: wired 17 CMMC practices into `/v1/compliance` endpoint — 14 frameworks now accessible via API (#933)
- **Sync HTTP client**: `create_sync_client()`, `sync_request_with_retry()`, `fetch_bytes()`, `fetch_json()` in `http_client.py` (#932)

## [0.71.2] – 2026-03-16

### Fixed
- **Symlink cycle in parser walk** — `_walk()` now tracks visited real paths via `os.path.realpath()` to prevent the same directory being scanned up to 5× through symlinks (#876)
- **Transitive dep fetch failures now logged** — silent `except (ValueError, KeyError): pass` in npm/PyPI fetch functions replaced with `_logger.warning()`; gather exceptions also routed through logger in addition to console (#879)

### Docs
- ARCHITECTURE.md — added `agent-bom run` node to CLI Commands subgraph wired to Runtime Proxy
- SKILL.md — bumped version, Docker tag, Sigstore reference, and test count to current values

---

## [0.71.1] – 2026-03-15

### Fixed
- **GHSA false positives (authlib, pyjwt)** — GitHub Advisory API now returns `patched_versions=null`; `vulnerable_version_range` is the authoritative field. Added `_installed_version_is_affected()` helper parsing compound constraints (`<=`, `<`, `>=`, `>`). Fixed packages already past the vulnerable window no longer flagged (#895)
- **Empty-version packages passed to scanners** — packages with `version=""` were unconditionally matched against all advisories. Added `""` to the scannable exclusion filter in `scanners/__init__.py`
- **NVIDIA scanner unconditional matches** — CSAF vulns with a `fixed_version` now call `compare_versions()` before appending; unversioned packages skipped
- **Proxy credential detection in error responses** — `check_credentials` was only applied to `"result"` fields; JSON-RPC `"error"` objects can carry exception messages with API keys. Now applies to both (#896)
- **Rate limit advisory-only** — `--rate-limit` logged alerts but never blocked. Enforcement block path added matching replay-detection pattern (#896)
- **Audit log rotation silent failure** — `except OSError: pass` replaced with `logger.warning()` to surface disk-full/permission errors (#896)

---

## [0.70.4] – 2026-03-11

### Added
- **Cloud provisioning scripts** — read-only, least-privilege provisioning for all 11 providers (AWS IAM + EKS RBAC, Azure Managed Identity, GCP Workload Identity, Snowflake key-pair JWT, Databricks PAT/OAuth, HuggingFace fine-grained token, W&B Viewer service account, Nebius IAM, CoreWeave namespace RBAC, NVIDIA NGC Viewer key) in `scripts/provision/`
- **Nebius pagination** — cursor-based pagination with `nextPageToken`/`next_page_token` wired into all 3 discovery functions
- **Post-merge self-scan** — GitHub Actions workflow scans agent-bom with agent-bom on every merge; blocks release on critical CVE (#648)
- **Two-tier severity gate** — `--warn-on` for CI warning gates, `--fail-on-severity` for hard failures (#625)
- **External scanner JSON ingestion** — import supported scanner JSON output with blast radius enrichment (#624)
- **Delta scanning** — `--delta` flag reports only new findings since last scan; exit code based on new-only (#630)
- **Local embedded vulnerability database** — SQLite schema, OSV/EPSS/KEV sync, fast lookup (#631)
- **Bun, NuGet (.NET), pip-compile parsers** (#660)
- **Gradle and conda parsers** for AI/ML ecosystems (#659)
- **go.sum integrity verification** + GOPROXY version resolution (#658)
- **Maven Central and crates.io** version resolution for unpinned deps (#661)
- **GHSA and NVD local DB sync** sources (#653)
- **Multi-source asset deduplication** — cross-cloud dedup with stable IDs (#654)
- **Deterministic UUID v5 stable IDs** for assets and findings (#655)
- **Auto-refresh stale vuln DB flag** — `--auto-refresh-db`, NIM/NeMo/NemoClaw NVIDIA tracking
- **Production-quality Go/Maven/RPM** parser improvements (#656)

### Fixed
- **Credential security** — URL validation (jira.py, slack.py), timing-safe metrics token compare (proxy.py), API key sanitization from exception messages (vector_db.py) (#662)
- **Databricks enum bug** — `EndpointStateReady.value` fix; `str(enum)` returned full name not value, causing all serving endpoints to be skipped (#664)
- **CoreWeave/NVIDIA provisioning** — kubeconfig + namespace RBAC, NGC Viewer key, DCGM exposure detection (#664)
- **Normalization gaps** — CLI check, scan_agents, rescan, postgres cache (#615)
- **GHSA PEP 503 normalization** — advisory matching + resolver debug logging (#619)
- **Multi-arch container rescan** — arm64 support, SARIF to Security tab (#650)
- **OTel hardening** — schema validation, file size cap, framework expansion (#642)
- **Stale DB warning** on outdated local cache (#642)
- **Local vuln DB security** — chmod 0600, HTTPS-only sync, path validation, integrity check (#634)
- **HTML report** — delta/warn-gate banners, vendor_severity display (#632)
- **Silent exception handlers** — logging added to all bare `except` blocks (#620)
- **Documentation accuracy** — detector count (6→7), architecture client and tool counts (#657)
- **MCP tool count** — replaced hardcoded counts with dynamic assertions (#626)

### Changed
- **`cli/scan.py` refactored** — 3,079L monolith → modular `scan/` package (#651)
- **Unified Finding model Phase 1** — core dataclasses, BlastRadius migration shim, dual-write (#628)
- **PEP 503 name normalization** — configurable batch size, unresolved package warnings (#614)
- **server.py routes extracted** — scan, discovery, connectors, governance, enterprise, schedules, observability, assets (#612, #613)

---

## [0.60.1] – 2026-03-08

### Fixed
- **P0: Ecosystem case normalization** — packages with ecosystem `"PyPI"` (uppercase) were silently returning 0 vulnerabilities. Fixed with `.lower()` normalization at every `ECOSYSTEM_MAP` lookup in `query_osv_batch` and `scan_packages`.
- **P0: OSV detail enrichment** — OSV `/v1/querybatch` returns only `{id, modified}` per vuln (no summary, CVSS, aliases). Added parallel detail fetching via `/v1/vulns/{id}` (semaphore=10), called at every return path including cache-hit early returns.
- **P0: Cache blocking I/O** — SQLite cache writes now run off the event loop via `asyncio.to_thread` + batched `put_many()` transaction, preventing event loop stalls on large scans.
- **Zero test failures** — `test_accuracy_baseline.py` fully fixed: lowercase ecosystem, `asyncio.run()`, correct `Severity` enum values.

### Added
- **Update notifications** — background daemon thread checks PyPI on startup, 24-hour file cache at `~/.cache/agent-bom/`, non-blocking notice shown on clean exit.
- **Improved `--version` output** — shows Python version, platform, and external scanner install status.
- **Better first-run UX** — zero-config scan shows actionable quick-start commands.

### Changed
- `CONTRIBUTING.md` rewritten — Quick start (5 min), good-first-issue guide, architecture table, DCO, security report path.

---

## [0.60.0] – 2026-03-07

### Added
- OpenSSF Best Practices passing badge (100% criteria met)
- ClusterFuzzLite integration for continuous fuzz testing
- ARCHITECTURE.md for contributor orientation
- SAST CWE map expanded from 10 → 52 entries
- 11 GitHub area labels for issue triage
- Good-first-issue and help-wanted issues for new contributors

### Changed
- Split OpenClaw monolith SKILL.md into 4 focused skills (scan, compliance, registry, runtime)
- Reduced SKILL.md surface area for better OpenClaw trust score

### Fixed
- ResponseInspector detector for cloaking and payload detection (wired into proxy)

---

## [0.59.3] – 2026-03-07

### Added
- Redesigned SVG diagrams: architecture, blast radius, topology, scan pipeline, compliance heatmap — dark and light variants
- Animated demo SVG
- Simplified README
- Dashboard charts and compliance matrix (Next.js)
- Grafana template
- MkDocs documentation site
- GitHub issue and PR templates
- Roadmap accuracy fixes

### Fixed
- Credential pattern detection improvements
- Policy conditions corrected to 17

---

## [0.59.2] – 2026-03-07

### Added
- Value-based credential scanning
- Smithery/ClawHub/MCP Registry retry logic
- Fleet scan and CIS benchmark input bounds
- NVD cache 90-day TTL
- Docker health check hardening
- ClawHub SKILL.md trust transparency

---

## [0.59.1] – 2026-03-06

### Added
- MCP tool reachability and capability scanning via `mcp_introspect.py`
- VEX (OpenVEX) support: load, generate, apply, export
- SBOM ingest: CycloneDX 1.x and SPDX 2.x/3.0 JSON
- OpenSSF Scorecard → risk boost integration
- OTel trace ingestion and CVE cross-reference

---

## [0.59.0] – 2026-03-06

### Added
- Runtime proxy with 7 detectors: ToolDrift, ArgumentAnalyzer, CredentialLeak, RateLimit, SequenceAnalyzer, ResponseInspector, VectorDBInjectionDetector
- Snowflake Native App integration
- Fleet scan across multiple agent inventories
- CIS benchmark checks (AWS)
- Policy-as-code: 17 conditions (16 declarative + expression engine)
- Prometheus metrics export from proxy
- JSONL audit log from proxy

---

[Unreleased]: https://github.com/msaad00/agent-bom/compare/v0.94.0...HEAD
[0.94.0]: https://github.com/msaad00/agent-bom/compare/v0.93.5...v0.94.0
[0.93.5]: https://github.com/msaad00/agent-bom/compare/v0.93.0...v0.93.5
[0.93.0]: https://github.com/msaad00/agent-bom/compare/v0.92.0...v0.93.0
[0.92.0]: https://github.com/msaad00/agent-bom/compare/v0.91.0...v0.92.0
[0.91.0]: https://github.com/msaad00/agent-bom/compare/v0.90.0...v0.91.0
[0.90.0]: https://github.com/msaad00/agent-bom/compare/v0.89.2...v0.90.0
[0.89.2]: https://github.com/msaad00/agent-bom/compare/v0.89.1...v0.89.2
[0.89.1]: https://github.com/msaad00/agent-bom/compare/v0.89.0...v0.89.1
[0.89.0]: https://github.com/msaad00/agent-bom/compare/v0.88.6...v0.89.0
[0.88.6]: https://github.com/msaad00/agent-bom/compare/v0.88.5...v0.88.6
[0.88.5]: https://github.com/msaad00/agent-bom/compare/v0.88.4...v0.88.5
[0.88.4]: https://github.com/msaad00/agent-bom/compare/v0.88.3...v0.88.4
[0.88.3]: https://github.com/msaad00/agent-bom/compare/v0.88.1...v0.88.3
[0.88.1]: https://github.com/msaad00/agent-bom/compare/v0.88.0...v0.88.1
[0.88.0]: https://github.com/msaad00/agent-bom/compare/v0.87.1...v0.88.0
[0.87.1]: https://github.com/msaad00/agent-bom/compare/v0.87.0...v0.87.1
[0.87.0]: https://github.com/msaad00/agent-bom/compare/v0.86.5...v0.87.0
[0.86.5]: https://github.com/msaad00/agent-bom/compare/v0.86.4...v0.86.5
[0.86.4]: https://github.com/msaad00/agent-bom/compare/v0.86.3...v0.86.4
[0.86.3]: https://github.com/msaad00/agent-bom/compare/v0.86.2...v0.86.3
[0.86.2]: https://github.com/msaad00/agent-bom/compare/v0.86.1...v0.86.2
[0.86.1]: https://github.com/msaad00/agent-bom/compare/v0.86.0...v0.86.1
[0.86.0]: https://github.com/msaad00/agent-bom/compare/v0.85.0...v0.86.0
[0.85.0]: https://github.com/msaad00/agent-bom/compare/v0.84.6...v0.85.0
[0.84.6]: https://github.com/msaad00/agent-bom/compare/v0.84.5...v0.84.6
[0.84.5]: https://github.com/msaad00/agent-bom/compare/v0.84.4...v0.84.5
[0.84.4]: https://github.com/msaad00/agent-bom/compare/v0.84.3...v0.84.4
[0.84.3]: https://github.com/msaad00/agent-bom/compare/v0.84.2...v0.84.3
[0.84.2]: https://github.com/msaad00/agent-bom/compare/v0.84.1...v0.84.2
[0.84.1]: https://github.com/msaad00/agent-bom/compare/v0.84.0...v0.84.1
[0.84.0]: https://github.com/msaad00/agent-bom/compare/v0.83.4...v0.84.0
[0.83.4]: https://github.com/msaad00/agent-bom/compare/v0.83.3...v0.83.4
[0.83.3]: https://github.com/msaad00/agent-bom/compare/v0.83.2...v0.83.3
[0.83.2]: https://github.com/msaad00/agent-bom/compare/v0.83.1...v0.83.2
[0.83.1]: https://github.com/msaad00/agent-bom/compare/v0.83.0...v0.83.1
[0.83.0]: https://github.com/msaad00/agent-bom/compare/v0.82.1...v0.83.0
[0.82.1]: https://github.com/msaad00/agent-bom/compare/v0.82.0...v0.82.1
[0.82.0]: https://github.com/msaad00/agent-bom/compare/v0.81.3...v0.82.0
[0.76.4]: https://github.com/msaad00/agent-bom/compare/v0.76.2...v0.76.4
[0.76.2]: https://github.com/msaad00/agent-bom/compare/v0.76.1...v0.76.2
[0.76.1]: https://github.com/msaad00/agent-bom/compare/v0.76.0...v0.76.1
[0.76.0]: https://github.com/msaad00/agent-bom/compare/v0.75.15...v0.76.0
[0.75.15]: https://github.com/msaad00/agent-bom/compare/v0.75.14...v0.75.15
[0.75.14]: https://github.com/msaad00/agent-bom/compare/v0.75.13...v0.75.14
[0.75.13]: https://github.com/msaad00/agent-bom/compare/v0.75.12...v0.75.13
[0.75.12]: https://github.com/msaad00/agent-bom/compare/v0.75.0...v0.75.12
[0.75.0]: https://github.com/msaad00/agent-bom/compare/v0.72.0...v0.75.0
[0.74.1]: https://github.com/msaad00/agent-bom/compare/v0.74.0...v0.74.1
[0.74.0]: https://github.com/msaad00/agent-bom/compare/v0.73.0...v0.74.0
[0.73.0]: https://github.com/msaad00/agent-bom/compare/v0.72.0...v0.73.0
[0.72.0]: https://github.com/msaad00/agent-bom/compare/v0.71.4...v0.72.0
[0.71.4]: https://github.com/msaad00/agent-bom/compare/v0.71.3...v0.71.4
[0.71.3]: https://github.com/msaad00/agent-bom/compare/v0.71.2...v0.71.3
[0.71.2]: https://github.com/msaad00/agent-bom/compare/v0.71.1...v0.71.2
[0.71.1]: https://github.com/msaad00/agent-bom/compare/v0.70.4...v0.71.1
[0.70.4]: https://github.com/msaad00/agent-bom/compare/v0.60.1...v0.70.4
[0.60.1]: https://github.com/msaad00/agent-bom/compare/v0.60.0...v0.60.1
[0.60.0]: https://github.com/msaad00/agent-bom/compare/v0.59.3...v0.60.0
[0.59.3]: https://github.com/msaad00/agent-bom/compare/v0.59.2...v0.59.3
[0.59.2]: https://github.com/msaad00/agent-bom/compare/v0.59.1...v0.59.2
[0.59.1]: https://github.com/msaad00/agent-bom/compare/v0.59.0...v0.59.1
[0.59.0]: https://github.com/msaad00/agent-bom/releases/tag/v0.59.0
