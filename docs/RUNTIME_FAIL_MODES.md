# Gateway fail-open / fail-closed posture

Every gateway enforcement subsystem decides what happens when its *own*
machinery fails — a policy file that will not load, a store that errors, an
evaluator that raises. The canonical inventory is code, not prose:

- **Matrix:** `agent_bom.runtime.fail_mode.GATEWAY_FAIL_MODE_MATRIX`
- **Live view:** `GET /healthz` on the gateway, under `fail_mode_runtime`
  (resolved against the running `AGENT_BOM_GATEWAY_FAIL_MODE`)
- **Regression pin:** `tests/test_runtime_fail_mode.py`

## Summary

| Subsystem | Default posture | Follows `AGENT_BOM_GATEWAY_FAIL_MODE` |
|---|---|---|
| Policy engine (unloadable policy file) | fail-closed | yes |
| Firewall policy (unloadable policy file) | fail-closed | yes |
| Policy plugins (evaluation error) | fail-closed | yes |
| Control-plane policy bundle (parse/eval error) | fail-closed | no |
| Invalid, expensive, or oversized regex in an applicable policy | enforce: deny; audit: explicit invalid-policy receipt | no |
| Conditional access (evaluation error) | fail-closed | no |
| Caller identity (invalid/revoked or missing token) | fail-closed | no |
| Runtime rate limit (store unavailable) | fail-closed (refuses startup) | no |
| Device posture enrichment (device state unknown) | fail-closed | no |
| Spend budgets (cost-store error) | fail-open | no |
| Cost-anomaly enforcement (cost-store error) | fail-open | no |
| Fleet quarantine (fleet-store error, enforce mode) | fail-closed | no |
| Drift enforcement (drift-store error) | fail-open | no |
| Graph reachability (evaluation error) | fail-open | no |
| Audit export (sink/webhook delivery failure) | fail-open | no |

Two rules explain the split:

- **Security decision lanes fail closed** and are never softened by
  `AGENT_BOM_GATEWAY_FAIL_MODE`. Only the policy engine, firewall policy
  load, and policy plugins honour that knob, and its default is `closed`.
- **Advisory and telemetry lanes fail open** by design: a spend-, drift-,
  or audit-store error must never take the data plane down. A
  successfully evaluated enforce-mode rule in those lanes still blocks.

Per-entry failure behavior (the `on_failure` text) is part of the matrix and
shows verbatim in the `/healthz` output. For the surface map around the
gateway see [`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md); for policy-layer
ordering inside a single tool call see `docs/POLICY_PRECEDENCE.md`.

## Conditional-access header authority

Gateway transport authentication does not authorize a client to assert its own
MFA, directory groups, managed device, approved client, environment or risk score.
By default, `x-agent-*` policy-context headers provide no trusted access evidence.
Policies requiring those attributes deny when they are unavailable; numeric risk
constraints require finite scores and finite numeric bounds, including a maximum.

After configuring incoming gateway authentication as described in
[`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md), configure the controlled
identity/posture proxy transport-peer CIDRs explicitly:

```bash
AGENT_BOM_GATEWAY_TRUSTED_CONTEXT_PROXY_CIDRS=10.42.0.10/32 \
  agent-bom gateway serve --upstreams upstreams.yaml --bind 0.0.0.0:8090
```

The proxy must authenticate and
bind these assertions to the caller, remove client-supplied `x-agent-*` headers,
and overwrite them with verified values. Restrict direct access to the gateway.
A trusted network is an operator-controlled boundary, not proof of MFA by itself.
The setting accepts at most 32 comma-separated IPv4/IPv6 networks, is resolved at
startup, and rejects invalid or unrestricted `/0` networks. Programmatic
`GatewaySettings.trusted_context_proxy_cidrs=()` overrides the environment and
disables this trust. Restart to apply configuration changes.

The gateway CLI disables Uvicorn's automatic forwarded-peer rewriting so the
transport peer remains available for this decision. Custom ASGI launchers must
also preserve the original peer (for Uvicorn, `--no-proxy-headers`).
`X-Forwarded-For` cannot establish context authority; existing trusted-proxy
settings only resolve the client IP used by separate source-CIDR conditions.

## What is *not* an isolation boundary

The stdio proxy's launcher check (`agent_bom.security.require_recognized_launcher`)
and shell-metacharacter argument check are launch-hygiene guards against
misconfigured server entries. They confer no isolation: a recognized launcher
(`python`, `node`, `docker`) can still run arbitrary code as the host user.
The execution control for MCP servers is container isolation —
`agent_bom.proxy_sandbox` via `--isolate` (see `docs/MCP_SECURITY_MODEL.md`).

## Gateway settings at startup

`agent-bom gateway serve --fleet-enforcement enforce` blocks quarantined
identities and denies calls when the fleet lookup is unavailable. `warn`
records the condition without blocking; `off` explicitly disables that check.
The gateway validates enforcement and DLP modes before creating audit sinks or
upstream clients. Python integrations normalize mode case and surrounding
whitespace; unknown modes, non-finite timeouts, invalid pool sizes, and negative
rate limits reject startup instead of silently disabling protection. Settings
representations omit credentials, policy contents, and credential-bearing URLs.
Correct the named setting and restart; mode errors never echo its supplied value.

### Invalid policy expressions

Policy creation and updates reject malformed regular expressions and patterns longer than 500 characters before changing stored state. Correct the indicated rule and retry the write. Existing stored policies and local JSON policy files receive the same validation at evaluation time: blocking rules fail closed; advisory rules produce an explicit invalid-policy warning. Disabled policies and policies bound to a different agent do not apply. Invalid-policy diagnostics omit patterns, argument names and argument values.

### Bounded regular-expression evaluation

Policy writes and stored/local policy evaluation reject nested repetitions,
alternation inside repetitions, counted repetitions above 1,000, and expression
nesting beyond 32 levels. The existing 500-character pattern limit still applies.
Rewrite an affected rule using simpler patterns before enabling enforcement.
For example, replace `^(a+)+$` with `^a+$`. This is a conservative grammar guard,
not a claim to identify every expensive expression.

The matcher uses the timeout-capable [regex engine](https://pypi.org/project/regex/)
in Python-compatible VERSION0 mode, with 25 ms per match and a shared 100 ms
budget per policy evaluation. Inputs beyond 10,000 characters and exhausted
budgets produce an explicit evaluation-limit decision; they never count as
non-matches. Enforce mode denies; audit mode permits with an explicit receipt.
These limits are operational safeguards, not a gateway throughput guarantee.
The bounded 512-entry compiled-pattern cache is process-local. Diagnostics omit
regex text, argument names, and argument values; policy and rule IDs identify
the affected configuration. Existing policy records are preserved for correction.
