# ADR-002: Custom JSON policy engine over OPA

## Status

Accepted

## Context

agent-bom needs a policy engine to evaluate security rules against scan findings
(e.g., "fail if any CRITICAL CVE exists", "warn if EPSS > 0.7 and has credentials").
Options considered:

1. **Open Policy Agent (OPA/Rego)** — industry standard, powerful, but requires learning
   Rego language, adds a Go binary dependency, and is heavyweight for our use case
2. **Custom JSON policy engine** — declarative JSON rules with a built-in expression
   evaluator, no external dependencies
3. **Python-native rules (code)** — flexible but not user-configurable without code changes

## Decision

Build a **custom JSON policy engine** (`policy.py`) with:

- 17 declarative conditions (`severity_gte`, `is_kev`, `has_credentials`, `min_agents`,
  `ecosystem`, `owasp_tag`, etc.)
- A `condition` expression engine supporting AND/OR/NOT, comparisons, and field access
  (e.g., `"epss_score > 0.7 and has_credentials and severity >= CRITICAL"`)
- Actions: `fail` (exit code 1), `warn` (log + continue), `jira` (create ticket)
- Policy files are plain JSON — no new language to learn

## Consequences

### Positive

- Zero external dependencies — no OPA binary, no Rego learning curve
- JSON policy files are readable by security teams without programming knowledge
- Expression engine covers 95%+ of real policy needs
- `--policy` CLI flag and `.agent-bom.yaml` project config make it easy to adopt
- Jira action enables automated ticket creation on policy violations

### Negative

- Less expressive than Rego for complex logic (nested quantifiers, aggregation)
- No ecosystem of pre-built policy bundles like OPA has
- Custom implementation means we maintain the parser ourselves
