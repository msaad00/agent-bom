# AGENT_BOM_* environment variable reference

> Generated from `src/agent_bom/config.py` by
> `scripts/generate_env_var_reference.py`. Do not edit by hand — re-run the
> generator and commit the diff. CI fails if this file is out of date or if
> a new `AGENT_BOM_*` reference appears in `src/agent_bom/` without being
> declared in `config.py` or added to `scripts/env_var_allowlist.txt`.

This is the canonical operator reference for the tuning knobs in
`src/agent_bom/config.py`. Helm values, deployment runbooks, and procurement
evidence should link here rather than redocument env vars locally.

For dynamic operational env vars that intentionally live outside `config.py`
(secrets, runtime feature flags, deploy-only toggles, OIDC/SAML/SCIM
credentials, etc.), see `scripts/env_var_allowlist.txt`. Those are tracked
so they cannot regress silently, but they are not part of this reference.

## AI Enrichment
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_AI_CACHE_MAX` | `int` | `1000` | Used by ai_enrich.py for LLM-powered risk narratives.  Cache bounded at 1,000 entries (sha256 keyed) to prevent unbounded memory growth during large scans.  Ollama default URL assumes local Docker/native install. |
| `AGENT_BOM_OLLAMA_URL` | `str` | `'http://localhost:11434'` | — |

## API Server Limits
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_ALLOW_UNAUTHENTICATED_API` | `bool` | `False` | — |
| `AGENT_BOM_API_JOB_TTL` | `int` | `3600` | — |
| `AGENT_BOM_API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT` | `int` | `API_MAX_CONCURRENT_JOBS` | — |
| `AGENT_BOM_API_MAX_BATCH_SCAN_TARGETS` | `int` | `100` | Per-request fan-out ceiling: a single POST /v1/scan expands one batchable target field per child job, so an uncapped request could enqueue unbounded work bounded only by the tenant active-scan quota churn. Reject over-cap requests at valida |
| `AGENT_BOM_API_MAX_FLEET_AGENTS_PER_TENANT` | `int` | `1000` | — |
| `AGENT_BOM_API_MAX_JOBS` | `int` | `10` | Used by api/server.py for the REST API job queue.  10 concurrent scan jobs prevents resource exhaustion on shared hosts. 1-hour TTL auto-cleans completed jobs.  200 in-memory ceiling triggers LRU eviction for long-running API instances. |
| `AGENT_BOM_API_MAX_JOB_PROGRESS_EVENTS` | `int` | `500` | — |
| `AGENT_BOM_API_MAX_MEMORY_JOBS` | `int` | `200` | — |
| `AGENT_BOM_API_MAX_OCSF_INGEST_EVENTS` | `int` | `1000` | — |
| `AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT` | `int` | `500` | — |
| `AGENT_BOM_API_MAX_SCHEDULES_PER_TENANT` | `int` | `100` | — |
| `AGENT_BOM_API_SCAN_CLAIM_POLL_SECONDS` | `int` | `3` | — |
| `AGENT_BOM_API_SCAN_LEASE_SECONDS` | `int` | `600` | Distributed scan dispatch (multi-replica work-stealing). When enabled, scan jobs are enqueued to a shared Postgres dispatch queue and any control-plane replica claims them via FOR UPDATE SKIP LOCKED, so scan throughput scales with replicas  |
| `AGENT_BOM_API_SCAN_WORKERS` | `int` | `min(4, os.cpu_count() or 2)` | — |
| `AGENT_BOM_API_SCAN_WORKER_RECYCLE_JOBS` | `int` | `10` | — |
| `AGENT_BOM_AWS_EVENT_MAX_BATCHES` | `int` | `10` | — |
| `AGENT_BOM_AWS_EVENT_MAX_MESSAGES` | `int` | `10` | Event-driven AWS posture ingestion (continuous posture). When an operator wires EventBridge→SQS (opt-in via AGENT_BOM_AWS_EVENT_QUEUE_URL, read live, default off), the bounded SQS consumer drains change events and re-evaluates only the affe |
| `AGENT_BOM_AWS_EVENT_VISIBILITY_TIMEOUT` | `int` | `120` | — |
| `AGENT_BOM_AWS_EVENT_WAIT_SECONDS` | `int` | `5` | — |
| `AGENT_BOM_AZURE_EVENT_MAX_BATCHES` | `int` | `10` | — |
| `AGENT_BOM_AZURE_EVENT_MAX_MESSAGES` | `int` | `10` | Event-driven Azure posture ingestion. When an operator wires Azure Monitor Activity Log / Event Grid → a Storage Queue (opt-in via AGENT_BOM_AZURE_EVENT_QUEUE, read live, default off), the bounded queue consumer drains change events and re- |
| `AGENT_BOM_AZURE_EVENT_VISIBILITY_TIMEOUT` | `int` | `120` | — |
| `AGENT_BOM_BODY_MIN_BPS` | `int` | `256` | Slowloris throughput floor (audit-5 PR-C): minimum sustained body bytes/second once a request body crosses the warmup threshold inside MaxBodySizeMiddleware. 0 disables the floor entirely (escape hatch for legitimate slow clients in restric |
| `AGENT_BOM_CONNECTIONS_SCHEDULER_MAX_CONCURRENCY` | `int` | `4` | — |
| `AGENT_BOM_CONNECTIONS_SCHEDULER_MIN_INTERVAL_MINUTES` | `int` | `15` | — |
| `AGENT_BOM_CONNECTIONS_SCHEDULER_POLL_SECONDS` | `int` | `60` | Cloud-connection scan scheduler (Phase B.2). The background loop re-scans cloud connections that carry an interval, so "connect once, keeps evaluating" is automatic. Disabled by default (AGENT_BOM_CONNECTIONS_SCHEDULER, read live) so it nev |
| `AGENT_BOM_FINDINGS_APPROXIMATE_TOTAL_THRESHOLD` | `int` | `50000` | Skip exact COUNT(*) on /v1/findings once cached total exceeds this threshold (0 = disabled). |
| `AGENT_BOM_GCP_EVENT_MAX_BATCHES` | `int` | `10` | — |
| `AGENT_BOM_GCP_EVENT_MAX_MESSAGES` | `int` | `10` | Event-driven GCP posture ingestion. When an operator wires Cloud Asset Inventory feed / audit logs → a Pub/Sub subscription (opt-in via AGENT_BOM_GCP_EVENT_SUBSCRIPTION, read live, default off), the bounded Pub/Sub consumer drains change ev |
| `AGENT_BOM_NO_AUTH_ROLE` | `str` | `'viewer'` | Role granted when unauthenticated API access is explicitly enabled. Default preserves local/dev compatibility; demo-estate mode clamps this to viewer. |

## Agent-to-Agent (A2A) auth posture
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_A2A_AUTH_MAX_BOUND_AGENTS` | `int` | `10` | — |
| `AGENT_BOM_A2A_AUTH_MAX_DELEGATION_DEPTH` | `int` | `4` | Governance thresholds for the A2A auth posture evaluator (agent_bom.a2a_auth_posture). agent-bom does not broker A2A auth; it scans discovered agents + gateway/proxy policies + delegation chains and flags weak inter-agent authentication as  |
| `AGENT_BOM_A2A_AUTH_REQUIRE_SIGNED_TOKENS` | `bool` | `True` | — |
| `AGENT_BOM_A2A_AUTH_SHARED_TOKEN_MIN_AGENTS` | `int` | `2` | — |

## Analytics Retention
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_ANALYTICS_MAX_EVENTS` | `int` | `50000` | Caps local analytics mirrors and runtime observation tables on write. ClickHouse analytics tables carry their own TTL clauses; this knob bounds SQLite/Postgres growth. ``<= 0`` disables pruning. |

## Blast Radius Risk Scoring
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_RISK_AGENT_CAP` | `float` | `2.0` | — |
| `AGENT_BOM_RISK_AGENT_WEIGHT` | `float` | `0.5` | Reach amplifiers — each affected entity adds *weight*, capped at *cap*. agent  0.5 × n (cap 2.0)  → 4+ agents = full amplification cred   0.3 × n (cap 1.5)  → 5+ creds  = full amplification tool   0.1 × n (cap 1.0)  → 10+ tools = full ampli |
| `AGENT_BOM_RISK_AI_BOOST` | `float` | `0.5` | Conditional boosts — applied when specific conditions are met. AI boost (0.5): AI framework package with both creds AND tools exposed. KEV boost (1.0): Vulnerability in CISA Known Exploited Vulnerabilities. EPSS boost (0.5): EPSS score ≥ EP |
| `AGENT_BOM_RISK_BASE_CRITICAL` | `float` | `8.0` | Used by models.BlastRadius.calculate_risk_score().  Design rationale: Base severity starts at 80 % of max (CRITICAL = 8.0 / 10.0) to leave headroom for reach amplifiers.  Each step down drops ~2 points so that a MEDIUM finding can still rea |
| `AGENT_BOM_RISK_BASE_HIGH` | `float` | `6.0` | — |
| `AGENT_BOM_RISK_BASE_LOW` | `float` | `2.0` | — |
| `AGENT_BOM_RISK_BASE_MEDIUM` | `float` | `4.0` | — |
| `AGENT_BOM_RISK_CRED_CAP` | `float` | `1.5` | — |
| `AGENT_BOM_RISK_CRED_WEIGHT` | `float` | `0.3` | — |
| `AGENT_BOM_RISK_EPSS_BOOST` | `float` | `0.5` | — |
| `AGENT_BOM_RISK_KEV_BOOST` | `float` | `1.0` | — |
| `AGENT_BOM_RISK_REACHABLE_BOOST` | `float` | `0.5` | Graph-walk reachability adjustment — applied only when `agent_bom.graph.dependency_reach.compute_dependency_reach` has stamped the BlastRadius with a definitive answer (None leaves scoring unchanged). reachable    → +0.5  (an agent's USES/D |
| `AGENT_BOM_RISK_SCORECARD_B1` | `float` | `0.75` | — |
| `AGENT_BOM_RISK_SCORECARD_B2` | `float` | `0.5` | — |
| `AGENT_BOM_RISK_SCORECARD_B3` | `float` | `0.25` | — |
| `AGENT_BOM_RISK_SCORECARD_T1` | `float` | `3.0` | Scorecard boost — poorly-maintained packages amplify risk. < 3.0 → +0.75  (abandoned / no CI / no SAST) < 5.0 → +0.50  (minimal maintenance) < 7.0 → +0.25  (below average) ≥ 7.0 → +0.00  (well-maintained) |
| `AGENT_BOM_RISK_SCORECARD_T2` | `float` | `5.0` | — |
| `AGENT_BOM_RISK_SCORECARD_T3` | `float` | `7.0` | — |
| `AGENT_BOM_RISK_TOOL_CAP` | `float` | `1.0` | — |
| `AGENT_BOM_RISK_TOOL_WEIGHT` | `float` | `0.1` | — |
| `AGENT_BOM_RISK_UNREACHABLE_PENALTY` | `float` | `0.5` | — |

## Cloud audit-trail behavioral ingestion (opt-in, read-only)
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_AUDIT_TRAIL` | `bool` | `False` | Master opt-in. When False (default), audit-trail ingestion is a clean no-op. Reuses the existing read-only connect role — no new IAM role, and (in standard setups) no new permission. |
| `AGENT_BOM_AUDIT_TRAIL_LOOKBACK_HOURS` | `int` | `24` | Lookback window (hours) for audit events; the reader clamps to two weeks. |
| `AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS` | `int` | `2000` | Per-provider event cap; the reader clamps to a hard ceiling and warns when hit. |

## Collector push mTLS
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_PUSH_TLS_CA_FILE` | `str` | `''` | Custom CA bundle used to verify the control-plane push endpoint. |
| `AGENT_BOM_PUSH_TLS_CERT_FILE` | `str` | `''` | Optional client certificate and custom CA bundle used when pushing local discovery/finding payloads to a hosted/self-hosted control plane. Empty strings keep the standard HTTPS trust store and no client certificate. |
| `AGENT_BOM_PUSH_TLS_KEY_FILE` | `str` | `''` | Client certificate private key path; used with PUSH_TLS_CERT_FILE. |

## DSPM content sampling
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_DSPM_DB_MAX_CELL_CHARS` | `int` | `4096` | — |
| `AGENT_BOM_DSPM_DB_MAX_ROWS_PER_TABLE` | `int` | `100` | — |
| `AGENT_BOM_DSPM_GCS_MAX_BYTES_PER_OBJECT` | `int` | `64 * 1024` | — |
| `AGENT_BOM_DSPM_GCS_MAX_OBJECTS_PER_BUCKET` | `int` | `10` | — |
| `AGENT_BOM_DSPM_S3_MAX_BYTES_PER_OBJECT` | `int` | `64 * 1024` | — |
| `AGENT_BOM_DSPM_S3_MAX_OBJECTS_PER_BUCKET` | `int` | `10` | Content reads are opt-in at the caller/module level. These caps bound the amount of object-store data read when an operator enables object-store sampling. |

## Demo Estate
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_DEMO_ESTATE` | `bool` | `False` | Enables curated demo-estate bootstrap on loopback / hosted proof paths. Off by default so production deployments never seed synthetic estate data unless an operator explicitly opts in. |

## EPSS Thresholds
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_EPSS_ACTIVE_THRESHOLD` | `float` | `0.5` | EPSS (Exploit Prediction Scoring System) probability thresholds. Source: https://www.first.org/epss/  0.5  — roughly the top 5 % of all scored CVEs; strong signal of real-world exploitation activity, comparable to CISA KEV inclusion criteri |
| `AGENT_BOM_EPSS_CRITICAL_THRESHOLD` | `float` | `0.7` | — |
| `AGENT_BOM_EPSS_HIGH_THRESHOLD` | `float` | `0.3` | — |

## Enrichment Cache
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_ENRICHMENT_MAX_CACHE` | `int` | `10000` | — |
| `AGENT_BOM_ENRICHMENT_TTL` | `int` | `604800` | Used by enrichment.py for persistent NVD + EPSS disk cache.  7-day TTL balances freshness vs. API rate limits.  10,000 entries covers most enterprise scans without unbounded disk/memory growth. |

## Extension Loading
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_ACTIVATE_ADVISORY_SOURCE_PLUGINS` | `bool` | `False` | — |
| `AGENT_BOM_ACTIVATE_MCP_TOOL_PLUGINS` | `bool` | `False` | Per-group runtime activation for discovered plugin entry points. Each is a second, explicit opt-in on top of discovery: even with discovery enabled, an operator must set the group flag before agent-bom binds and executes a third-party MCP t |
| `AGENT_BOM_ACTIVATE_RUNTIME_EMITTER_PLUGINS` | `bool` | `False` | — |
| `AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS` | `bool` | `False` | Disabled by default so third-party provider/connector/parser entry points never execute unless an operator explicitly opts in. |

## Graph Backend Selection
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH` | `bool` | `False` | — |
| `AGENT_BOM_GRAPH_BACKEND` | `str` | `''` | SQLite is the local default. Postgres remains selected by AGENT_BOM_POSTGRES_URL. Neptune is experimental and requires explicit opt-in plus endpoint config. SQLite and Postgres remain the supported graph backends. |
| `AGENT_BOM_NEPTUNE_ENDPOINT` | `str` | `''` | — |
| `AGENT_BOM_NEPTUNE_TRAVERSAL_SOURCE` | `str` | `'g'` | — |

## Graph Retention
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_GRAPH_RETENTION_DAYS` | `int` | `180` | Age-based graph snapshot retention for self-hosted graph stores. Per-tenant overrides resolve from ``AGENT_BOM_GRAPH_RETENTION_OVERRIDES`` (JSON map) and the control-plane tenant retention store before this global default. |

## HTTP Client
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT` | `float` | `45.0` | — |
| `AGENT_BOM_HTTP_DEFAULT_TIMEOUT` | `float` | `30.0` | — |
| `AGENT_BOM_HTTP_INITIAL_BACKOFF` | `float` | `1.0` | — |
| `AGENT_BOM_HTTP_MAX_BACKOFF` | `float` | `30.0` | — |
| `AGENT_BOM_HTTP_MAX_RETRIES` | `int` | `3` | Used by http_client.create_client() and request_with_retry().  Defaults: 3 retries with 1s initial backoff (doubles each retry, capped at 30s).  30s per-request timeout covers most external APIs; NVD can be slow so operators may raise this. |
| `AGENT_BOM_HTTP_RATE_LIMIT_BREAKER_THRESHOLD` | `int` | `3` | Registry rate-limit circuit breaker: number of HTTP 429 responses from a single host within one scan before live lookups to that host are short- circuited to the cached/bundled fallback path for the rest of the run. Keeps a registry throttl |

## Hub Observations Retention
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_HUB_OBSERVATIONS_RETENTION_DAYS` | `int` | `365` | Age-based retention for the Postgres occurrence log (``hub_findings_current_observations``). Monthly RANGE partitions are detached and dropped once wholly past this window. ``<= 0`` disables rollover. SQLite and legacy unpartitioned Postgre |

## Image Scanning
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_IMAGE_GRYPE_FALLBACK` | `bool` | `False` | Optional Grype fallback for ``agent-bom image --tar`` when native OCI/archive extraction yields no packages. Off by default — enable only when bridging legacy tarballs that Grype handles better than the native parser. |

## Local Analytics
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_LOCAL_ANALYTICS_DB` | `str` | `''` | Optional path override for the local scan analytics SQL mirror. Empty string means use ~/.agent-bom/local-analytics.sqlite. |

## MCP / agent→MCP auth posture
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_MCP_AUTH_FLAG_LOCAL_STDIO` | `bool` | `False` | Governance thresholds for the MCP server auth posture evaluator (agent_bom.mcp_auth_posture). This is the complement of the A2A evaluator: A2A covers inter-AGENT auth, this covers MCP SERVER auth + the agent→MCP edge per the MCP authorizati |
| `AGENT_BOM_MCP_AUTH_REQUIRE_NETWORK_AUTH` | `bool` | `True` | — |
| `AGENT_BOM_MCP_AUTH_REQUIRE_TLS` | `bool` | `True` | — |

## MCP Server Limits
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_MCP_CALLER_RATE_LIMIT` | `int` | `120` | — |
| `AGENT_BOM_MCP_CALLER_WINDOW_SECONDS` | `float` | `60.0` | — |
| `AGENT_BOM_MCP_GLOBAL_RATE_LIMIT` | `int` | `MCP_CALLER_RATE_LIMIT * 20` | Process-wide ceiling across all MCP callers, enforced in addition to the per-caller window. Backstops a flood that spreads across many distinct (or unverified per-connection) caller identities. Defaults to a generous multiple of the per-cal |
| `AGENT_BOM_MCP_GLOBAL_WINDOW_SECONDS` | `float` | `MCP_CALLER_WINDOW_SECONDS` | — |
| `AGENT_BOM_MCP_MAX_CALLER_STATES` | `int` | `256` | — |
| `AGENT_BOM_MCP_MAX_CONCURRENT_TOOLS` | `int` | `8` | — |
| `AGENT_BOM_MCP_MAX_FILE_SIZE` | `int` | `50 * 1024 * 1024` | Used by mcp_server.py for file-size and response-size guards, tool execution governance, and lightweight in-process observability.  50 MB max file size prevents accidental ingestion of large binaries. 500,000 char response cap keeps MCP too |
| `AGENT_BOM_MCP_MAX_REQUEST_TRACES` | `int` | `256` | — |
| `AGENT_BOM_MCP_MAX_RESPONSE` | `int` | `500000` | — |
| `AGENT_BOM_MCP_MAX_TOOL_METRICS` | `int` | `128` | — |
| `AGENT_BOM_MCP_TOOL_TIMEOUT_SECONDS` | `float` | `30.0` | — |

## OIDC discovery shim
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_OIDC_DISCOVERY_SHIM_JSON` | `str` | `''` | Optional static OIDC discovery metadata JSON served by the gateway for legacy IdPs / MCP clients that need discovery documents but cannot publish them at the normal issuer location. Empty string disables the shim. |

## OS-package reporting
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_INCLUDE_UNFIXED` | `bool` | `False` | When False (default), OS/distro advisories with no fix for the scanned release (no-dsa / won't-fix / end-of-life open) are suppressed so container reporting matches mainstream scanner conventions. Set AGENT_BOM_INCLUDE_UNFIXED=1 to surface  |

## PostgreSQL Control Plane Tuning
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_DELTA_STREAM_AUTH_SCHEME` | `str` | `''` | — |
| `AGENT_BOM_DELTA_STREAM_AUTH_TOKEN` | `str` | `''` | — |
| `AGENT_BOM_DELTA_STREAM_DESTINATION_ID` | `str` | `'delta-stream-default'` | — |
| `AGENT_BOM_DELTA_STREAM_ENABLED` | `bool` | `False` | Finding delta-stream export to SIEM / data-lake sinks (#3514). |
| `AGENT_BOM_DELTA_STREAM_FORMAT` | `str` | `'ndjson'` | — |
| `AGENT_BOM_DELTA_STREAM_SIGNING_SECRET` | `str` | `''` | — |
| `AGENT_BOM_DELTA_STREAM_URL` | `str` | `''` | — |
| `AGENT_BOM_HUB_REFERENCE_NORMALIZE` | `bool` | `True` | Compliance hub reference-table normalization (#3513). When enabled, repeated CVE/framework blobs are stored once per tenant and ledger rows keep join keys. Set to 0 to disable new extractions (reads still hydrate existing refs). |
| `AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS` | `int` | `5` | — |
| `AGENT_BOM_POSTGRES_GRAPH_SEARCH_TIMEOUT_MS` | `int` | `3000` | — |
| `AGENT_BOM_POSTGRES_POOL_MAX_SIZE` | `int` | `20` | — |
| `AGENT_BOM_POSTGRES_POOL_MIN_SIZE` | `int` | `5` | Used by api/postgres_store.py and shared Postgres-backed control-plane services such as the distributed rate limiter.  Defaults target multi-replica self-hosted control planes rather than a single local developer process. |
| `AGENT_BOM_POSTGRES_STATEMENT_TIMEOUT_MS` | `int` | `15000` | — |

## Public-repo clone-and-scan bounds
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_REPO_SCAN_CLONE_TIMEOUT_SECONDS` | `float` | `120.0` | Max wall-clock seconds for the `git clone` step before it is aborted. |
| `AGENT_BOM_REPO_SCAN_MAX_FILES` | `int` | `100000` | Max number of files in the cloned working tree. |
| `AGENT_BOM_REPO_SCAN_MAX_SIZE_BYTES` | `int` | `1024 * 1024 * 1024` | Max total on-disk size (bytes) of the cloned working tree. Default 1 GiB. |

## Rate-limit fingerprint key rotation policy
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS` | `int` | `90` | — |
| `AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS` | `int` | `30` | Operators rotate AGENT_BOM_RATE_LIMIT_KEY periodically and record the rotation timestamp in AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED (ISO-8601 with timezone). The control plane warns when the configured key age approaches the rotation interval |

## Report export artifacts
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_API_MAX_ACTIVE_REPORT_JOBS_PER_TENANT` | `int` | `5` | — |
| `AGENT_BOM_REPORT_ARTIFACT_DIR` | `str` | `''` | Async findings report exports are written to a local artifact directory and downloaded through job-scoped tokens. Empty string means use the per-user default ~/.agent-bom/report-artifacts. The worker re-reads the env var at runtime so tests |
| `AGENT_BOM_REPORT_S3_BUCKET` | `str` | `''` | When REPORT_S3_BUCKET is set, completed exports are uploaded to customer S3 and job status returns a presigned GET URL. Credentials follow the standard AWS SDK chain (IRSA, instance profile, env keys). Requires boto3 (``[aws]`` extra). |
| `AGENT_BOM_REPORT_S3_PREFIX` | `str` | `'report-artifacts'` | — |
| `AGENT_BOM_REPORT_S3_PRESIGN_SECONDS` | `int` | `3600` | — |
| `AGENT_BOM_REPORT_S3_REGION` | `str` | `''` | — |

## Runtime → graph incident feedback
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_RUNTIME_FEEDBACK_PATH` | `str` | `''` | The feedback direction of the agentic moat: the runtime ProtectionEngine appends observed incidents (credential reach, lateral movement, kill-switch) to a durable JSONL sink at this path; the next scan's graph builder ingests them so the gr |

## Scan Cache
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_SCAN_CACHE_MAX_ENTRIES` | `int` | `100000` | SQLite-backed OSV result cache (~/.agent-bom/scan_cache.db).  100,000 entries covers ~5-10 large enterprise scans before eviction kicks in. Oldest entries are removed first (LRU by insertion time) when the limit is hit. Set to 0 to disable  |

## Scanner Batching
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_ENABLE_CPE_MATCH` | `bool` | `False` | Opt-in CPE candidate matching against the local NVD CPE cache. Off by default: CPE product names don't always equal package names, so these are review-grade (nvd_cpe_candidate) and only applied to components OSV/distro feeds miss. |
| `AGENT_BOM_GHSA_UNAUTH_PACKAGE_BUDGET` | `int` | `25` | Cap unauthenticated GHSA advisory lookups so no-token scans fail fast with partial coverage instead of spending minutes on GitHub rate limits. |
| `AGENT_BOM_SCANNER_BATCH_DELAY` | `float` | `0.5` | — |
| `AGENT_BOM_SCANNER_BATCH_SIZE` | `int` | `1000` | OSV API max is 1000 |
| `AGENT_BOM_SCANNER_MAX_CONCURRENT` | `int` | `10` | Used by scanners/__init__.py for OSV batch API concurrency.  10 concurrent requests with 500ms delay between batches keeps us well under OSV.dev's rate limit while still being fast for large inventories. |
| `AGENT_BOM_SCANNER_OSV_BATCH_CONCURRENCY` | `int` | `3` | — |

## Server Risk Scoring
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_SERVER_COMBO_CAP` | `float` | `1.5` | — |
| `AGENT_BOM_SERVER_COMBO_WEIGHT` | `float` | `0.3` | — |
| `AGENT_BOM_SERVER_CRED_CAP` | `float` | `2.0` | — |
| `AGENT_BOM_SERVER_CRED_WEIGHT` | `float` | `0.5` | — |
| `AGENT_BOM_SERVER_CRITICAL` | `float` | `9.0` | Risk level thresholds for server risk classification. |
| `AGENT_BOM_SERVER_HIGH` | `float` | `7.0` | — |
| `AGENT_BOM_SERVER_MEDIUM` | `float` | `4.0` | — |
| `AGENT_BOM_SERVER_REG_HIGH` | `float` | `6.0` | Registry floor — when the bundled MCP registry says a server is "high" or "medium" risk, enforce a minimum score regardless of tool analysis. |
| `AGENT_BOM_SERVER_REG_MEDIUM` | `float` | `3.0` | — |
| `AGENT_BOM_SERVER_RISK_CEILING` | `float` | `7.0` | Used by risk_analyzer.score_server_risk().  Base ceiling 7.0 normalises the capability-weighted sum so that a server with ALL capability types still only reaches 7.0 before amplifiers. |
| `AGENT_BOM_SERVER_TOOL_CAP` | `float` | `1.5` | — |
| `AGENT_BOM_SERVER_TOOL_WEIGHT` | `float` | `0.15` | — |

## Shield async bridge limits
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_SHIELD_ASYNC_BRIDGE_MAX_WORKERS` | `int` | `4` | The synchronous Shield SDK can be called from inside a running event loop. Use a small shared pool for that bridge instead of spawning a fresh unbounded executor per call. |
