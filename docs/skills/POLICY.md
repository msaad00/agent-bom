# Skills Scanner Policy Gates

`agent-bom skills scan` supports policy-aware warning and blocking gates for
AI instruction files and skills. The scanner keeps content risk, provenance,
and handling guidance separate:

- `content_verdict`: behavioral content risk (`benign`, `suspicious`,
  `malicious`)
- `provenance_verdict`: source/signing posture (`verified`, `unverified`)
- `review_verdict`: handling recommendation (`trusted`, `review`,
  `high_risk`, `blocked`)

Use review gates when a CI pipeline should route unsigned or high-risk skills
to review without claiming the skill content is malicious.

## CLI

Warn, but do not fail, when a skill needs review:

```bash
agent-bom skills scan . --warn-on-review-verdict review
```

Block on high-risk or blocked handling verdicts:

```bash
agent-bom skills scan . --fail-on-review-verdict high_risk
```

Apply a policy file:

```bash
agent-bom skills scan . --policy skills-policy.yaml -f json -o skills.json
```

## Policy File

```yaml
defaults:
  warn_on_review_verdict: review
  fail_on_review_verdict: blocked

rules:
  - id: block-prompt-coercion
    action: block
    reason: Prompt coercion is not allowed in production skills.
    match:
      category: prompt_coercion

  - id: warn-undocumented-network
    action: warn
    match:
      category: undocumented_network

suppressions:
  - owner: security
    reason: Public documentation URL accepted for this approved skill.
    expires: 2026-12-31
    match:
      category: undocumented_network
      path_contains: docs/skills/
```

Suppression entries must include `owner`, `reason`, and a future `expires`
date. Expired or ownerless suppressions are ignored.

Supported rule match fields:

- `category`
- `severity`
- `severity_gte`
- `verdict`
- `content_verdict`
- `review_verdict`
- `provenance_verdict`
- `path`
- `path_contains`
- `fingerprint`

Actions are `warn`, `fail`, or `block`; `block` is treated as a failing gate.

## GitHub Action

Run skills scanning as its own CI lane:

```yaml
- uses: msaad00/agent-bom@v0.94.2
  with:
    scan-type: skills
    scan-ref: .
    format: sarif
    output: agent-bom-skills.sarif
    upload-sarif: true
    policy: skills-policy.yaml
    warn-on-review-verdict: review
    fail-on-review-verdict: blocked
```

Skills SARIF includes finding source locations, trust metadata, and policy
results for GitHub code scanning. Keep IaC/SBOM/package gates in separate jobs
when the desired policies or review owners differ.
