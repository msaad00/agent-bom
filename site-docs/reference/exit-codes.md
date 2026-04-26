# CLI Exit Codes and HTTP Status Mapping

agent-bom exposes the same domain through a CLI, an HTTP API, an MCP server, and a
GitHub Action. CI gates and shell pipelines branch on `agent-bom`'s exit code; HTTP
clients branch on the API's status code. This page is the single contract that
documents both, so a script writer never has to read the source to know what an
exit code means.

## CLI exit-code contract

The contract covers ok, findings, usage, auth, and server failures explicitly so
automation can distinguish caller mistakes from control-plane outages.

| Code  | Name                | Meaning                                                                                                       | Typical sources                                                            |
| ----- | ------------------- | ------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| `0`   | success             | Command completed; no findings or all findings under the configured severity threshold.                        | Any subcommand that finished cleanly.                                      |
| `1`   | operational failure | A precondition failed: missing config, unreachable backend, missing required env var, dependency not present.  | `--clickhouse-url` missing, NVD unreachable, optional dependency not installed. |
| `2`   | usage or empty      | Invalid arguments, no input to act on, or report contained no rows after filtering.                            | Click `UsageError` (auto), `agent-bom skills audit` with no skill files, empty result rendering. |
| `3`   | (reserved)          | Reserved for "policy gate failed" — declared so future policy commands have a stable code to use.              | Not yet emitted.                                                           |
| `4`   | (reserved)          | Reserved for "auth required" / "auth invalid" on commands that talk to an authenticated control plane.        | Not yet emitted.                                                           |
| `5`   | (reserved)          | Reserved for "remote control-plane error" (5xx response from the API).                                         | Not yet emitted.                                                           |
| `130` | interrupted         | Process received `SIGINT` (`Ctrl-C`) — POSIX convention, kept for shell idiom compatibility.                  | Long-running `agent-bom proxy` / `agent-bom serve` / `agent-bom scan`.      |
| `*`   | subprocess passthrough | When agent-bom shells out (e.g. native scanner binaries), the child's non-zero exit code is propagated.    | `agent-bom shield`, `agent-bom run` proxy invocations.                     |

The unreserved codes (`0`, `1`, `2`, `130`) are stable today. Codes `3`, `4`, `5` are
reserved so future product growth has a clean place to land without re-numbering
existing codes — operators may rely on `if [ "$rc" -eq 0 ]` and on the
`rc != 0` family without further branching today.

## API status-code contract

| Status | Meaning                                                                                          | Where it's raised                                                              |
| ------ | ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ |
| `200`  | Success.                                                                                         | All successful reads and writes.                                               |
| `201`  | Created.                                                                                         | `POST /v1/scan`, `POST /v1/auth/keys`, SCIM `POST /Users`/`/Groups`.            |
| `204`  | Deleted.                                                                                         | DELETEs that succeed without a body.                                           |
| `400`  | Bad request — payload validation passed Pydantic but failed business-rule validation.            | Tenant-quota update with negative caps, invalid filter combinations.           |
| `401`  | Unauthenticated — no valid API key, OIDC bearer, SAML session, or trusted-proxy attestation.     | Middleware before route resolution.                                            |
| `403`  | Authenticated but not authorized — RBAC scope rule rejected the call.                            | Cross-tenant access attempt, viewer role attempting admin operation.           |
| `404`  | Resource not found.                                                                              | Scan job, agent, registry server, key, or graph node not present in tenant.    |
| `409`  | Conflict — idempotency clash, duplicate key creation, concurrent state mutation.                 | API key rotation, scan-job lifecycle conflicts.                                |
| `422`  | Pydantic validation failure — payload shape rejected.                                            | FastAPI request-body validation.                                               |
| `429`  | Rate limited — per-tenant quota or global rate limit hit.                                        | Middleware `PostgresRateLimitStore`.                                           |
| `500`  | Server error — unexpected exception inside route logic.                                          | Bugs, downstream timeouts that escape retry budgets.                           |
| `502`  | Upstream bad-gateway — proxied call (e.g. external scanner) returned an unparseable response.    | External scanner adapters.                                                     |
| `503`  | Backend unavailable — Postgres, ClickHouse, or another required dependency is down.              | Health probes, dependency-aware routes.                                        |

All errors return `{"detail": "<message>"}` per FastAPI default. The UI client at
`ui/lib/api.ts` parses `detail`, `message`, and `error` so that any of those keys
surface to operators with a useful string.

## How CLI codes correspond to API statuses

This is the explicit mapping that the CLI applies when it talks to the API and
needs to translate an HTTP outcome into a process exit code. It's not a reflexive
1:1 mapping — several HTTP codes collapse into a single CLI code because shells
care about families, not individual semantics.

| CLI exit code | HTTP status family                                | Why                                                                                            |
| ------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------- |
| `0`           | `2xx`                                             | The command did what it asked.                                                                 |
| `2`           | `400` `422`                                       | Caller sent something invalid — usage error, fix the input.                                    |
| `4` (reserved) | `401` `403`                                       | Caller is not (or not yet) authorized — fix credentials, not the input.                       |
| `1`           | `404` `409`                                       | Operational state issue — resource missing, conflict — retryable after correcting state.       |
| `1`           | `429`                                             | Throttled — retry with backoff. Today flattens to `1`; future revisions may use a dedicated code. |
| `5` (reserved) | `5xx`                                             | Control-plane fault — agent-bom is not at fault, retry or escalate.                            |
| `130`         | n/a                                               | Operator pressed `Ctrl-C`; never originates from an HTTP response.                              |

Until reserved codes (`3`/`4`/`5`) are emitted, the safe shell idiom is:

```bash
agent-bom scan ./project --output sarif > out.sarif
rc=$?
case "$rc" in
  0)   echo "ok" ;;
  2)   echo "usage / empty"; exit 0 ;;     # treat empty as non-failure in some pipelines
  130) echo "interrupted"; exit 130 ;;     # propagate Ctrl-C semantics
  *)   echo "failed (rc=$rc)"; exit "$rc" ;;
esac
```

## GitHub Action `action.yml` outputs

The composite action surfaces both the CLI exit code and a parsed-status output so
downstream steps can branch without re-parsing logs. When agent-bom finds findings
above the configured severity floor the step still exits `0` — the action sets
`outputs.findings` for the caller to gate on. Hard failures (`rc != 0` and not an
empty/usage outcome) bubble up so the workflow turns red.

| Output         | Type   | Source                               | Notes                                                                                  |
| -------------- | ------ | ------------------------------------ | -------------------------------------------------------------------------------------- |
| `findings`     | string | parsed from JSON / SARIF             | `"true"` when at least one finding crosses the configured severity floor.              |
| `report-path`  | string | computed                             | Absolute path to the JSON / SARIF / HTML report inside the runner workspace.           |
| `sarif-path`   | string | computed                             | Absolute path to the SARIF report when `--output sarif` was selected.                  |
| `exit-code`    | string | propagated CLI exit code             | Same value documented in [CLI exit-code contract](#cli-exit-code-contract).            |

## Stability guarantees

- **`0`, `1`, `2`, `130`, and the subprocess passthrough are stable** and will not be
  re-numbered within a major version.
- **`3`, `4`, `5` are reserved** and will be assigned only to the meanings declared
  above.
- The HTTP status mapping is a binding contract for shell pipelines; future status
  codes added to the API will fold into the same families described above unless a
  new CLI code is introduced (in which case it will be drawn from the reserved set,
  not allocated above `5`).
