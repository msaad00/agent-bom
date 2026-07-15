# Observability → enforcement: security-eval scorecard + observe→enforce bridge

Two capabilities that turn what agent-bom *observes* about AI-agent runtime
behaviour into governance evidence and gateway policy, without adding any new
HTTP surface. Both ride existing outputs.

- **Security-eval scorecard** — packages a red-team run as a structured eval
  artifact that sits alongside quality/accuracy evals.
- **Observe→enforce bridge** — turns runtime↔scan correlation (tools that are
  *both* confirmed-vulnerable *and* actively invoked) into gateway block-rule
  proposals.

---

## 1. Security-eval scorecard

`agent_bom.security_eval_scorecard.build_security_eval_scorecard()` runs the
curated red-team attack catalog (`agent_bom.red_team`) through Shield and
packages the result as a schema-versioned artifact (`security-eval-scorecard/v1`).

It reports the three facets governance reviewers ask for:

| Facet | Field | Meaning |
|---|---|---|
| **Coverage %** | `coverage_pct` | `attacks_run / catalog_size` — a partial run scores below 100 %. |
| **False-positive rate** | `false_positive_rate`, `false_positives` | Benign cases that tripped a detector. |
| **Per-category pass/fail** | `per_category[cat]` | `{total, detected, passed, failed, pass}` per attack category. |

The artifact is **deterministic** (no clock, no randomness, offline — no LLM),
so it is safe inside release gates and diff-friendly.

`eval_type: "security"` marks it as a security eval so it can sit alongside
quality evals in the same eval feed.

### Where it surfaces

It rides the existing **accuracy-baseline eval artifact**
(`agent_bom.accuracy_baseline.build_accuracy_baseline`), surfaced as
`docs/accuracy-baseline.json` via `scripts/generate_accuracy_baseline.py`. The
scorecard is embedded under the `security_eval_scorecard` key, next to the
runtime red-team and scanner-corpus evidence:

```bash
python scripts/generate_accuracy_baseline.py          # regenerate
python scripts/generate_accuracy_baseline.py --check   # release gate
```

No new CLI subcommand or REST route was added.

---

## 2. Observe→enforce bridge

`agent_bom.observe_enforce.propose_block_rules()` consumes a
`agent_bom.runtime_correlation.CorrelationReport` and emits gateway block-rule
**proposals** for every tool that is:

1. **confirmed-vulnerable** — present in a correlated scan finding (a real CVE
   on a package the tool exposes), *and*
2. **actively-called** — invoked at least once (`call_count >= 1`) in the proxy
   audit traces.

A tool that is vulnerable but never called is theoretical risk only and gets no
proposal. Multiple CVEs on one tool collapse into a single rule (all CVE IDs are
cited in the rationale).

Each proposal reuses the existing `GatewayRule` model
(`{action: "block", block_tools: [tool]}`) and the proposals are bundled into a
single `GatewayPolicy` — the same representation the gateway already evaluates.
No new rule type, no new route.

### Security model: propose by default, enforce only on opt-in

| Mode | Trigger | Gateway effect |
|---|---|---|
| **Audit (default)** | always | Block rules are downgraded to advisory `warn` (see `gateway.gateway_policies_to_proxy_bundle`). Nothing is blocked. |
| **Enforce** | explicit opt-in | Rules block. Produced only when `enforce=True`. |

Even an enforce-mode result is inert until an operator imports and enables the
policy through the existing gateway policy layer. There is **no path that
auto-blocks production traffic without operator intent**.

### Where it surfaces (CLI reference)

The bridge rides the existing `--correlate` flag on the scan command:

```bash
# Propose only (default): warns which vulnerable+called tools would be blocked.
agent-bom agents --correlate proxy-audit.jsonl

# Emit an enforce-mode policy for review before import (explicit opt-in).
AGENT_BOM_ENFORCE_CORRELATED_BLOCKS=1 agent-bom agents --correlate proxy-audit.jsonl
```

Console output lists each proposed block rule (`block tool:<name> — <CVEs>
(called Nx)`). The full proposal set — including the generated `GatewayPolicy`
— is attached to the JSON report under
`runtime_correlation.observe_enforce` (`gateway.observe_enforce.v1`):

```json
{
  "runtime_correlation": {
    "observe_enforce": {
      "schema_version": "gateway.observe_enforce.v1",
      "mode": "audit",
      "enforced": false,
      "proposal_count": 1,
      "proposals": [
        {"tool_name": "read_file", "vulnerability_ids": ["CVE-2025-1"], "call_count": 3,
         "rule": {"id": "observe-enforce-read-file", "action": "block", "block_tools": ["read_file"]}}
      ],
      "policy": {"policy_id": "agent-bom-observe-enforce", "mode": "audit", "...": "..."}
    }
  }
}
```

`AGENT_BOM_ENFORCE_CORRELATED_BLOCKS` (`1`/`true`/`yes`/`on`) is the explicit
operator opt-in that flips the emitted policy from audit to enforce mode.
