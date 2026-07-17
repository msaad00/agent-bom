# AI enrichment

AI enrichment is optional and advisory by default. The scanner's deterministic
findings, severities, suppressions, and pass/fail result remain authoritative.

## First command, artifact, next step

Run a local-model enrichment:

```bash
agent-bom scan . --ai-enrich --ai-model ollama/llama3.2 --format json --output report.json
```

The JSON report adds `ai_finding_assessments`, keyed by deterministic
`finding_id`, plus `ai_enrichment_metadata`. Each assessment carries the task,
provider, model, confidence, false-positive likelihood, rationale, controls,
and `advisory: true`. Review these alongside `findings`; do not treat them as
replacements for scanner evidence.

If the explicitly selected provider is unavailable, the scan completes normally
without AI assessments. An `ollama/*` selection never falls back to a remote
provider. Model responses with unknown finding IDs are discarded. Raw finding
evidence is not sent to triage; outbound prompts use bounded fields and secret
redaction is enabled by default.

## Deterministic opt-in gate

AI skill-file reviews cannot change pass/fail by default. To opt in, both flags
are required:

```bash
agent-bom scan . --ai-enrich --ai-deterministic --ai-gate-findings
```

This sets model temperature to zero and allows AI false-positive reviews or
AI-detected skill findings to affect the skill audit and process exit gate. The
original result is retained as `deterministic_passed`, while `ai_gate_enabled`
records the opt-in. The general `ai_finding_assessments` surface always remains
advisory.

Temperature zero improves stability but is not a byte-reproducibility claim:
hosted providers and model revisions can change. Cache entries are isolated by
provider, model, optional model revision, task, effective temperature, redaction
posture, and prompt version. Assessment provenance records prompt/response
hashes and the observation time so an operator can identify drift.

## Routing, limits, and data boundary

| Setting | Default | Purpose |
|---|---:|---|
| `AGENT_BOM_AI_MODEL_CHEAP` | unset | Narrative and summary model |
| `AGENT_BOM_AI_MODEL_STRONG` | unset | Detection, triage, and config-analysis model |
| `AGENT_BOM_AI_MAX_CALLS` | `50` | Actual provider-request cap, including retries; `0` is unlimited and negative values are rejected |
| `AGENT_BOM_AI_MAX_FINDINGS` | `100` | Maximum deterministic findings offered to triage |
| `AGENT_BOM_AI_FINDING_BATCH_SIZE` | `20` | Findings per triage request, capped at 50 |
| `AGENT_BOM_AI_REDACT_PROMPTS` | `true` | Redact recognizable secrets before model calls |
| `AGENT_BOM_AI_DETERMINISTIC` | `false` | Set temperature zero for all enrichment calls |
| `AGENT_BOM_AI_MODEL_REVISION` | unset | Optional immutable provider/model revision recorded in cache posture and provenance |

`ai_enrichment_metadata.call_budget` reports provider attempts, retries, cache
hits, remaining attempts, exhaustion, and per-task counts. `triage_scope`
reports total, offered, truncated, and assessed finding counts. Provider
failures, invalid or oversized JSON, and exhausted budgets degrade to partial or
absent advice without weakening deterministic gates.

## Exact prompt data boundary

| Task | Prompt material | Remote eligible |
|---|---|---|
| Finding triage | Finding ID/type/source/severity, bounded title and description, bounded asset name/type, risk/reachability/KEV state, and up to 20 control tags; no raw evidence | Yes, only after explicit `--ai-enrich`/API opt-in and provider configuration |
| Narrative/summary | Bounded scan and vulnerability context, package coordinates, agent/tool names, and credential variable names; no credential values | Yes, after explicit opt-in |
| MCP config analysis | Up to 20 agents × 10 servers, sanitized command arguments, transport, tool names, and credential variable names | Yes, after explicit opt-in |
| Skill detection/review | Up to 6,000 characters per discovered skill file plus static finding summaries | **No. Local Ollama only; remote selections skip this task.** |

Recognizable credentials are redacted at every provider boundary. Secret
redaction is defense in depth, not a general source-code anonymizer, which is why
raw skill content is restricted to the local provider.

## Issue #3206 checkpoint

This checkpoint ships provider-boundary enforcement, prompt redaction,
retries/timeouts/posture-isolated cache, provider-attempt accounting, general
confidence-scored triage, versioned provenance, CLI/API controls, typed JSON
output, and the advisory-by-default/explicit-gate contract. It intentionally
does not claim an issue-completion percentage.

Paused remainder: ensemble/consensus scoring, compliance-control tagging,
general novel-finding detection beyond skill files, MCP execution controls,
persistent evaluation datasets, and operator quality/cost dashboards. Those
surfaces should ship only with task-specific evaluation evidence and stable
schemas; they are not represented as current product behavior.
