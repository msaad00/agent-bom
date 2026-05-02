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
| `AGENT_BOM_API_JOB_TTL` | `int` | `3600` | — |
| `AGENT_BOM_API_MAX_ACTIVE_SCAN_JOBS_PER_TENANT` | `int` | `API_MAX_CONCURRENT_JOBS` | — |
| `AGENT_BOM_API_MAX_FLEET_AGENTS_PER_TENANT` | `int` | `1000` | — |
| `AGENT_BOM_API_MAX_JOBS` | `int` | `10` | Used by api/server.py for the REST API job queue.  10 concurrent scan jobs prevents resource exhaustion on shared hosts. 1-hour TTL auto-cleans completed jobs.  200 in-memory ceiling triggers LRU eviction for long-running API instances. |
| `AGENT_BOM_API_MAX_JOB_PROGRESS_EVENTS` | `int` | `500` | — |
| `AGENT_BOM_API_MAX_MEMORY_JOBS` | `int` | `200` | — |
| `AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT` | `int` | `500` | — |
| `AGENT_BOM_API_MAX_SCHEDULES_PER_TENANT` | `int` | `100` | — |
| `AGENT_BOM_BODY_MIN_BPS` | `int` | `256` | Slowloris throughput floor (audit-5 PR-C): minimum sustained body bytes/second once a request body crosses the warmup threshold inside MaxBodySizeMiddleware. 0 disables the floor entirely (escape hatch for legitimate slow clients in restric |

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
| `AGENT_BOM_ENABLE_EXTENSION_ENTRYPOINTS` | `bool` | `False` | Disabled by default so third-party provider/connector/parser entry points never execute unless an operator explicitly opts in. |

## HTTP Client
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_CLOUD_DISCOVERY_TIMEOUT` | `float` | `45.0` | — |
| `AGENT_BOM_HTTP_DEFAULT_TIMEOUT` | `float` | `30.0` | — |
| `AGENT_BOM_HTTP_INITIAL_BACKOFF` | `float` | `1.0` | — |
| `AGENT_BOM_HTTP_MAX_BACKOFF` | `float` | `30.0` | — |
| `AGENT_BOM_HTTP_MAX_RETRIES` | `int` | `3` | Used by http_client.create_client() and request_with_retry().  Defaults: 3 retries with 1s initial backoff (doubles each retry, capped at 30s).  30s per-request timeout covers most external APIs; NVD can be slow so operators may raise this. |

## MCP Server Limits
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_MCP_CALLER_RATE_LIMIT` | `int` | `120` | — |
| `AGENT_BOM_MCP_CALLER_WINDOW_SECONDS` | `float` | `60.0` | — |
| `AGENT_BOM_MCP_MAX_CALLER_STATES` | `int` | `256` | — |
| `AGENT_BOM_MCP_MAX_CONCURRENT_TOOLS` | `int` | `8` | — |
| `AGENT_BOM_MCP_MAX_FILE_SIZE` | `int` | `50 * 1024 * 1024` | Used by mcp_server.py for file-size and response-size guards, tool execution governance, and lightweight in-process observability.  50 MB max file size prevents accidental ingestion of large binaries. 500,000 char response cap keeps MCP too |
| `AGENT_BOM_MCP_MAX_REQUEST_TRACES` | `int` | `256` | — |
| `AGENT_BOM_MCP_MAX_RESPONSE` | `int` | `500000` | — |
| `AGENT_BOM_MCP_MAX_TOOL_METRICS` | `int` | `128` | — |
| `AGENT_BOM_MCP_TOOL_TIMEOUT_SECONDS` | `float` | `30.0` | — |

## PostgreSQL Control Plane Tuning
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS` | `int` | `5` | — |
| `AGENT_BOM_POSTGRES_GRAPH_SEARCH_TIMEOUT_MS` | `int` | `3000` | — |
| `AGENT_BOM_POSTGRES_POOL_MAX_SIZE` | `int` | `20` | — |
| `AGENT_BOM_POSTGRES_POOL_MIN_SIZE` | `int` | `5` | Used by api/postgres_store.py and shared Postgres-backed control-plane services such as the distributed rate limiter.  Defaults target multi-replica self-hosted control planes rather than a single local developer process. |
| `AGENT_BOM_POSTGRES_STATEMENT_TIMEOUT_MS` | `int` | `15000` | — |

## Rate-limit fingerprint key rotation policy
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_RATE_LIMIT_KEY_MAX_AGE_DAYS` | `int` | `90` | — |
| `AGENT_BOM_RATE_LIMIT_KEY_ROTATION_DAYS` | `int` | `30` | Operators rotate AGENT_BOM_RATE_LIMIT_KEY periodically and record the rotation timestamp in AGENT_BOM_RATE_LIMIT_KEY_LAST_ROTATED (ISO-8601 with timezone). The control plane warns when the configured key age approaches the rotation interval |

## Scan Cache
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_SCAN_CACHE_MAX_ENTRIES` | `int` | `100000` | SQLite-backed OSV result cache (~/.agent-bom/scan_cache.db).  100,000 entries covers ~5-10 large enterprise scans before eviction kicks in. Oldest entries are removed first (LRU by insertion time) when the limit is hit. Set to 0 to disable  |

## Scanner Batching
| Env var | Type | Default | Description |
|---|---|---|---|
| `AGENT_BOM_GHSA_UNAUTH_PACKAGE_BUDGET` | `int` | `25` | Cap unauthenticated GHSA advisory lookups so no-token scans fail fast with partial coverage instead of spending minutes on GitHub rate limits. |
| `AGENT_BOM_SCANNER_BATCH_DELAY` | `float` | `0.5` | — |
| `AGENT_BOM_SCANNER_BATCH_SIZE` | `int` | `1000` | OSV API max is 1000 |
| `AGENT_BOM_SCANNER_MAX_CONCURRENT` | `int` | `10` | Used by scanners/__init__.py for OSV batch API concurrency.  10 concurrent requests with 500ms delay between batches keeps us well under OSV.dev's rate limit while still being fast for large inventories. |

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
