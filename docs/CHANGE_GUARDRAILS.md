# Change Guardrails

Use this checklist for any feature, fix, refactor, or infra change that can affect product behavior.

## Baseline

- Keep backend, CLI, UI, docs, schema, and tests aligned. Do not merge partial wiring without calling it out explicitly.
- Prefer additive, backwards-compatible changes unless a breaking change is intentional and documented.
- Rebase or update stale branches before merge when `main` has moved in related files, contracts, or dependencies.
- Avoid drift between code paths, deployment manifests, examples, and operator-facing help text.

## Security by design

- Default to least privilege, read-only, zero-trust, and agentless collection where possible.
- Fail closed for authz, tenancy, signature verification, and policy enforcement unless an explicitly documented advisory mode exists.
- Treat input as untrusted across API, CLI, UI, proxy, gateway, parsers, and connectors.
- Review common classes of abuse for touched surfaces:
  - auth bypass or privilege escalation
  - tenant isolation breaks
  - SQL injection or unsafe query construction
  - XSS or unsafe HTML rendering
  - SSRF, path traversal, command injection, and deserialization issues
  - prompt injection, tool poisoning, and unsafe model/tool context bridging
  - MITM or trust-boundary weakening around keys, sessions, JWKS, TLS, or signed bundles

## Scale and performance

- Prefer store-native filters, pagination, and bounded traversal over full snapshot loads on hot paths.
- Avoid unnecessary N+1 reads, repeated full scans, and duplicate parsing on request paths.
- Keep operator surfaces honest about runtime mode, cache behavior, and eventual consistency boundaries.
- If a safer fallback is less scalable, document the limitation and the intended follow-up.

## Validation

- Run targeted tests for the touched area, plus broader regression coverage when contracts or shared infrastructure move.
- Validate the real integration seams that were changed, not only isolated helpers.
- Keep CI, local validation, and production-facing behavior consistent.

## Exceptions

Exceptions are allowed only when they are optional, explicit, and documented.

Each exception should state:

- what is being relaxed
- why the exception exists
- scope and blast radius
- whether it is opt-in or default
- compensating controls
- follow-up issue or exit criteria

Examples:

- advisory-only runtime policy mode for staged rollout
- single-node local development auth shortcuts bound to loopback
- conservative fallback paths used until a store-native implementation lands
