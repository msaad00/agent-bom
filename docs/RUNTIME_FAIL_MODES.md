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
| Control-plane policy bundle (parse/regex/eval error) | fail-closed | no |
| Conditional access (evaluation error) | fail-closed | no |
| Caller identity (invalid/revoked or missing token) | fail-closed | no |
| Runtime rate limit (store unavailable) | fail-closed (refuses startup) | no |
| Device posture enrichment (device state unknown) | fail-closed | no |
| Spend budgets (cost-store error) | fail-open | no |
| Cost-anomaly enforcement (cost-store error) | fail-open | no |
| Fleet quarantine (fleet-store error) | fail-open | no |
| Drift enforcement (drift-store error) | fail-open | no |
| Graph reachability (evaluation error) | fail-open | no |
| Audit export (sink/webhook delivery failure) | fail-open | no |

Two rules explain the split:

- **Security decision lanes fail closed** and are never softened by
  `AGENT_BOM_GATEWAY_FAIL_MODE`. Only the policy engine, firewall policy
  load, and policy plugins honour that knob, and its default is `closed`.
- **Advisory and telemetry lanes fail open** by design: a spend-, drift-,
  fleet-, or audit-store error must never take the data plane down. A
  successfully evaluated enforce-mode rule in those lanes still blocks.

Per-entry failure behavior (the `on_failure` text) is part of the matrix and
shows verbatim in the `/healthz` output. For the surface map around the
gateway see [`RUNTIME_REFERENCE.md`](RUNTIME_REFERENCE.md); for policy-layer
ordering inside a single tool call see `docs/POLICY_PRECEDENCE.md`.

## What is *not* an isolation boundary

The stdio proxy's launcher check (`agent_bom.security.require_recognized_launcher`)
and shell-metacharacter argument check are launch-hygiene guards against
misconfigured server entries. They confer no isolation: a recognized launcher
(`python`, `node`, `docker`) can still run arbitrary code as the host user.
The execution control for MCP servers is container isolation —
`agent_bom.proxy_sandbox` via `--isolate` (see `docs/MCP_SECURITY_MODEL.md`).
