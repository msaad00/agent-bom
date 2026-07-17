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

If no configured model is available, the scan completes normally without AI
assessments. Model responses with unknown finding IDs are discarded. Raw
finding evidence is not sent to triage; outbound prompts use bounded fields and
secret redaction is enabled by default.

## Deterministic opt-in gate

AI skill-file reviews cannot change pass/fail by default. To opt in, both flags
are required:

```bash
agent-bom scan . --ai-enrich --ai-deterministic --ai-gate-findings
```

This sets model temperature to zero and allows AI false-positive reviews or
AI-detected skill findings to affect the skill audit. The original result is
retained as `deterministic_passed`, while `ai_gate_enabled` records the opt-in.
The general `ai_finding_assessments` surface always remains advisory.

## Routing, limits, and data boundary

| Setting | Default | Purpose |
|---|---:|---|
| `AGENT_BOM_AI_MODEL_CHEAP` | unset | Narrative and summary model |
| `AGENT_BOM_AI_MODEL_STRONG` | unset | Detection, triage, and config-analysis model |
| `AGENT_BOM_AI_MAX_CALLS` | `50` | Shared per-run call budget; `0` is unlimited |
| `AGENT_BOM_AI_MAX_FINDINGS` | `100` | Maximum deterministic findings offered to triage |
| `AGENT_BOM_AI_FINDING_BATCH_SIZE` | `20` | Findings per triage request, capped at 50 |
| `AGENT_BOM_AI_REDACT_PROMPTS` | `true` | Redact recognizable secrets before model calls |
| `AGENT_BOM_AI_DETERMINISTIC` | `false` | Set temperature zero for all enrichment calls |

`ai_enrichment_metadata.call_budget` reports calls used, remaining calls,
exhaustion, and per-task counts. Provider failures, invalid JSON, and exhausted
budgets degrade to partial or absent advice without weakening deterministic
gates.

## Issue #3206 checkpoint

This checkpoint is approximately 70% of the issue: provider routing, prompt
redaction, retries/timeouts/cache, run-wide budget accounting, general
confidence-scored triage, provenance, CLI/API controls, JSON output, and the
advisory-by-default gate contract are implemented.

Paused remainder: ensemble/consensus scoring, compliance-control tagging,
general novel-finding detection beyond skill files, MCP execution controls,
persistent evaluation datasets, and operator quality/cost dashboards. Those
surfaces should ship only with task-specific evaluation evidence and stable
schemas; they are not represented as current product behavior.
