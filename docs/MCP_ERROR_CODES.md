# MCP error codes and API parity

> Source of truth: `src/agent_bom/mcp_errors.py`. CI runs
> `tests/test_mcp_errors.py` to keep this document in sync — every code
> declared in `mcp_errors.py` must appear in the table below, and vice
> versa.

## Why stable codes

MCP tools previously returned `{"error": "free-form string"}` envelopes.
Clients had no way to programmatically branch on auth vs validation vs
upstream failures except by substring-matching the message. Closes #1960.

Every error returned from an MCP tool now uses the canonical envelope
defined in `agent_bom.mcp_errors.mcp_error_payload`:

```json
{
  "error": {
    "code":     "AGENTBOM_MCP_VALIDATION_INVALID_ECOSYSTEM",
    "category": "validation",
    "message":  "Invalid ecosystem: 'foo'. Valid: ...",
    "details":  {"argument": "ecosystem"}
  },
  "schema_version": 1
}
```

- `code` — machine-readable identifier; clients pin against this directly.
- `category` — coarse-grained bucket for catch-all branches; one of
  `auth`, `validation`, `timeout`, `upstream`, `rate_limited`, `not_found`,
  `unsupported`, `internal`.
- `message` — operator-readable text, already passed through
  `agent_bom.security.sanitize_error` so it's safe to log.
- `details` — optional structured context (argument name, retry-after
  seconds, upstream name, etc.).
- `schema_version` — bumps only when the envelope shape changes.

## Code → category reference

| Code | Category | When emitted |
|---|---|---|
| `AGENTBOM_MCP_VALIDATION_INVALID_ARGUMENT` | validation | Generic bad input where no more specific code fits. |
| `AGENTBOM_MCP_VALIDATION_INVALID_PATH` | validation | A path argument failed `safe_path` (traversal, oversize, missing). |
| `AGENTBOM_MCP_VALIDATION_INVALID_ECOSYSTEM` | validation | Ecosystem not in the supported set. |
| `AGENTBOM_MCP_VALIDATION_INVALID_VULN_ID` | validation | CVE/GHSA identifier failed format validation. |
| `AGENTBOM_MCP_VALIDATION_INVALID_IMAGE_REF` | validation | Container image reference failed `validate_image_ref`. |
| `AGENTBOM_MCP_VALIDATION_MISSING_REQUIRED` | validation | Required argument or one-of group missing. |
| `AGENTBOM_MCP_AUTH_REQUIRED` | auth | The MCP transport requires auth and the caller did not provide it. |
| `AGENTBOM_MCP_AUTH_FORBIDDEN` | auth | Caller authenticated but lacks the role/scope for this tool. |
| `AGENTBOM_MCP_RATE_LIMITED_CALLER` | rate_limited | Per-caller rate limit hit; respect `details.retry_after_seconds`. |
| `AGENTBOM_MCP_RATE_LIMITED_CONCURRENCY` | rate_limited | Server-wide tool concurrency cap hit; back off briefly. |
| `AGENTBOM_MCP_TIMEOUT_TOOL` | timeout | The tool exceeded `MCP_TOOL_TIMEOUT_SECONDS`. |
| `AGENTBOM_MCP_TIMEOUT_UPSTREAM` | timeout | An upstream (OSV, registry, cloud provider) timed out. |
| `AGENTBOM_MCP_UPSTREAM_UNAVAILABLE` | upstream | Upstream returned 5xx or connection failed. |
| `AGENTBOM_MCP_UPSTREAM_BAD_RESPONSE` | upstream | Upstream returned malformed payload. |
| `AGENTBOM_MCP_NOT_FOUND_RESOURCE` | not_found | The requested resource (CVE, server, package) is not in scope. |
| `AGENTBOM_MCP_NOT_FOUND_AGENTS` | not_found | No agents discovered in the current scan scope. |
| `AGENTBOM_MCP_UNSUPPORTED_BACKEND` | unsupported | Tool requires a backend that is not configured (analytics, ClickHouse, etc.). |
| `AGENTBOM_MCP_UNSUPPORTED_QUERY_TYPE` | unsupported | The supplied `query_type` is not in the allowed enum. |
| `AGENTBOM_MCP_INTERNAL_UNEXPECTED` | internal | Unhandled server-side error; treat as a bug. |

## Client branching pattern

```python
result = json.loads(mcp_response_text)
if "error" in result:
    err = result["error"]
    if err["category"] == "validation":
        # Fix the argument and retry
        ...
    elif err["category"] == "rate_limited":
        retry_after = err.get("details", {}).get("retry_after_seconds", 5)
        time.sleep(retry_after)
        ...
    elif err["category"] == "auth":
        # Re-establish credentials, do NOT retry blindly
        ...
    elif err["category"] in {"upstream", "timeout"}:
        # Transient: bounded retry with backoff
        ...
    elif err["category"] == "internal":
        # Surface to ops; do not loop
        ...
```

## API ↔ MCP parity matrix

agent-bom exposes its capabilities through three surfaces: the FastAPI
control plane (`/v1/...`), the MCP server (`agent-bom mcp server`), and
the CLI (`agent-bom ...`). They are deliberately not identical. This
matrix records what each surface exposes and why.

### Tools available on both API and MCP

| Capability | API | MCP tool | Notes |
|---|---|---|---|
| Run a scan | `POST /v1/scan` | `scan` | Same scan pipeline. |
| Look up CVE blast radius | `GET /v1/findings/{cve}` | `blast_radius` | MCP returns the same shape. |
| Query the MCP server registry | `GET /v1/registry/servers` | `registry_lookup`, `marketplace_check`, `fleet_scan` | Registry is read-only on both. |
| Compliance posture | `GET /v1/compliance/{framework}` / `GET /v1/compliance/aisvs` | `compliance` | 15 tag-mapped frameworks plus AISVS benchmark evidence (curated subsets — see [ARCHITECTURE.md § Coverage per framework](./ARCHITECTURE.md#coverage-per-framework)), both surfaces. |
| SBOM generation | `POST /v1/sbom` | `generate_sbom` | CycloneDX + SPDX on both. |
| Policy evaluation | `POST /v1/gateway/evaluate` | `policy_check` | Same `check_policy` evaluator. |

### MCP-only

| MCP tool | Why API does not expose it |
|---|---|
| `where`, `inventory` | Local discovery — depends on the MCP host's own filesystem and config dirs, which the API would not see anyway. |
| `tool_risk_assessment` | Live MCP server introspection — requires stdio access to the target server, which is the MCP host's job. |

### API-only

| API surface | Why MCP does not expose it |
|---|---|
| `POST /v1/auth/keys`, `POST /v1/auth/keys/{id}/rotate`, `DELETE /v1/auth/keys/{id}` | Key-store mutations are control-plane operations, not scanner operations. Exposing them through MCP would require running the MCP server as an admin, which violates the read-only stance documented in `mcp_server.py`. |
| `POST /v1/exceptions`, `PUT /v1/exceptions/{id}/approve`, `DELETE /v1/exceptions/{id}` | Same reason as auth — these mutate enforcement state. |
| `POST /v1/fleet/sync` | Multi-endpoint ingestion is a server-side join across many MCP hosts; an MCP tool that triggers ingestion would invert the intended push-from-edges shape. |
| `POST /v1/proxy/audit` | Audit append is HMAC-chained on the server side; exposing it via MCP would let one MCP host write audit entries on behalf of another. |
| `GET /v1/auth/policy`, `GET /v1/auth/secrets/lifecycle`, `GET /v1/auth/secrets/rotation-plan` | Operator/dashboard surfaces — meaningful only against the running control plane. |
| Streaming endpoints (`GET /v1/scan/{id}/stream`, `GET /v1/proxy/audit/stream`) | MCP tool calls are request/response, not streaming. The CLI uses these directly. |

### Why the asymmetry is deliberate

agent-bom's MCP server is a **read-only scanner surface** that an LLM can
invoke on behalf of a user. The API is the **control plane** for the
deployed product. The split is not "MCP is incomplete" — it's intentional
defense-in-depth so an MCP host compromise cannot mutate enforcement
state, rotate keys, or ingest false audit entries.
