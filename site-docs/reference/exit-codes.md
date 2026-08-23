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
| `0`   | success             | Command completed; no findings or all findings under the default or configured severity threshold.             | Any subcommand that finished cleanly; `scan --exit-zero` with vulnerability findings only. |
| `1`   | scan verdict or operational failure | Either (a) a scan gate matched — see "Why `scan` exits 1" below — or (b) a precondition failed: missing config, unreachable backend, missing required env var, dependency not present. | Default critical threshold or `--fail-on-severity` matched, an incomplete scan such as a missing or unreadable offline vulnerability database, `agent-bom scan --demo` (malicious package fails closed), `--clickhouse-url` missing, NVD unreachable, optional dependency not installed, `agent-bom connect <provider>` failing to verify or register. |
| `2`   | usage or empty      | Invalid arguments, no input to act on, or report contained no rows after filtering.                            | Click `UsageError` (auto), `agent-bom skills audit` with no skill files, empty result rendering, `agent-bom connect` when the control plane rejects the payload (`400`/`422`). |
| `3`   | policy gate failed  | An opt-in policy gate failed. Currently emitted by `--require-fresh-db` / `AGENT_BOM_REQUIRE_FRESH_DB` when the local vuln DB is stale. Otherwise reserved for future policy gates. | `agent-bom scan --require-fresh-db` against a stale local vuln DB.          |
| `4`   | (reserved)          | Reserved for "auth required" / "auth invalid" on commands that talk to an authenticated control plane.        | Not yet emitted.                                                           |
| `5`   | (reserved)          | Reserved for "remote control-plane error" (5xx response from the API).                                         | Not yet emitted.                                                           |
| `130` | interrupted         | Process received `SIGINT` (`Ctrl-C`) — POSIX convention, kept for shell idiom compatibility.                  | Long-running `agent-bom proxy` / `agent-bom serve` / `agent-bom agents`.    |
| `*`   | subprocess passthrough | When agent-bom shells out (e.g. native scanner binaries), the child's non-zero exit code is propagated.    | `agent-bom shield`, `agent-bom run` proxy invocations.                     |

### Why `scan` exits 1

`agent-bom scan --demo --offline` exits `1`. That is the scanner working, not
failing: the report is printed in full and the specific gate that matched is
named on the last line of the output. A scan exits `1` when any of these hold.

| Gate | Opt-in? | What it means |
| --- | --- | --- |
| Default critical severity gate / `--fail-on-severity` | Critical is the default; the flag selects another threshold | A vulnerability met or exceeded the active threshold. Use `--exit-zero` only for an explicitly reporting-only vulnerability scan. |
| `--fail-on-kev` / `--fail-if-ai-risk` matched | Yes — you set the flag | A finding met the additional gate you asked to block on. |
| A policy rule failed | Yes — `--policy`, or `--model-policy-mode enforce` / `--require-model-signatures` / `--block-unsafe-model-formats` (all default off) | Your policy rejected the result. |
| A known-malicious package was found | **No — fails closed** | A typosquat, dependency-confusion, or known-malicious advisory match. Exiting `0` here would let the package install. |
| The scan did not complete | **No — fails closed** | A requested collector degraded or failed; `scan_run.issues` in the artifact says which. A partial artifact with zero findings must not read as clean. |

A missing, empty, or unreadable local advisory database during `scan --offline`
is an incomplete scan, so `scan` writes a partial artifact when an output was
requested and exits `1`. It is not a usage error (`2`) because the command and
input were valid. The narrower `check` command retains its established
precondition contract and exits `2` when its requested offline advisory lookup
cannot start.

`scan` defaults to a `critical` vulnerability gate, so a report containing
critical findings exits non-zero even when no threshold flag was passed. The
malicious-package and incomplete-evidence gates also fail closed. Use
`--fail-on-severity` to choose a stricter threshold, or `--exit-zero` for an
explicitly reporting-only vulnerability scan. `--exit-zero` never suppresses a
malicious-package, policy, or incomplete-evidence failure. Add `--warn-on` when
the reporting-only path should still print a named warning tier.

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

Because `4` and `5` are still reserved, the families that would map to them
(`401`/`403` and `5xx`) **flatten to `1`** today rather than being emitted early.
A command that talks to the control plane is therefore always safe to gate on
`rc != 0`: `agent-bom connect <provider>` exits `2` when the control plane
rejects the payload and `1` for every other failure — a failed credential
verification, a rejected registration, an unreachable control plane, or a
missing provider SDK extra. It never exits `0` without a verified connection, so
`agent-bom connect aws && <next step>` cannot promote a broken connection. When
the control plane returns an actionable `detail`, the CLI prints that message
verbatim instead of a "see server logs" dead end.

Until reserved codes (`3`/`4`/`5`) are emitted, the safe shell idiom is:

```bash
agent-bom agents -p ./project --format sarif > out.sarif
rc=$?
case "$rc" in
  0)   echo "ok" ;;
  2)   echo "usage / empty"; exit 0 ;;     # treat empty as non-failure in some pipelines
  130) echo "interrupted"; exit 130 ;;     # propagate Ctrl-C semantics
  *)   echo "failed (rc=$rc)"; exit "$rc" ;;
esac
```

## GitHub Action `action.yml` outputs

The composite action surfaces the CLI exit code, parsed scan status, artifact
paths, and AI-specific posture counts so downstream workflow steps can gate
without re-parsing logs.

| Output | Type | Source | Notes |
|---|---|---|---|
| `sarif-file` | string | computed | Path to the SARIF report when `format: sarif` was selected. |
| `exit-code` | string | propagated CLI exit code | Same value documented in [CLI exit-code contract](#cli-exit-code-contract). |
| `scan-status` | string | parsed from exit code + findings | `clean`, `violations`, or `error`. |
| `vulnerability-count` | string | parsed from SARIF or skills JSON | Number of vulnerability findings, or skill findings for `scan-type: skills`. |
| `badge-file` | string | computed | Path to generated shields.io badge JSON when `badge` is set. |
| `graph-export-path` | string | computed | Path to generated `mermaid`, `svg`, `graph`, or `graph-html` artifact. |
| `exposure-paths-count` | string | parsed from graph-capable JSON | Number of exposure, lateral, or attack paths in the result artifact. |
| `blast-radius-critical-count` | string | parsed from SARIF/JSON | Number of critical blast-radius or SARIF findings. |
| `posture-grade` | string | derived from parsed counts | Coarse grade: `A`, `C`, `D`, `F`, or `unknown`. |

## Stability guarantees

- **`0`, `1`, `2`, `130`, and the subprocess passthrough are stable** and will not be
  re-numbered within a major version.
- **`3`, `4`, `5` are reserved** and will be assigned only to the meanings declared
  above.
- The HTTP status mapping is a binding contract for shell pipelines; future status
  codes added to the API will fold into the same families described above unless a
  new CLI code is introduced (in which case it will be drawn from the reserved set,
  not allocated above `5`).
