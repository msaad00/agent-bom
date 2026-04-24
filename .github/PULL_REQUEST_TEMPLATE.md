## Summary
<!-- What does this PR do? Keep it to 1-3 bullet points. -->

## Related Issues
<!-- Closes #XXX (auto-closes on merge) -->

## Test plan
<!-- How was this tested? -->

- [ ] `pytest tests/ -x -q` passes
- [ ] `ruff check src/ && ruff format --check src/` passes
- [ ] TypeScript: `cd ui && npx tsc --noEmit` (if UI changes)
- [ ] Manual verification (describe below)
- [ ] Targeted end-to-end or contract coverage added/updated when shared wiring changed

## Breaking changes
- [ ] None
- [ ] Yes — describe migration path below

## Checklist
- [ ] Version bumped if this is a release PR (`scripts/bump-version.py`)
- [ ] Docs/diagrams updated if features changed (`ARCHITECTURE.md`, `README.md`, SVGs)
- [ ] No secrets, credentials, or personally identifiable data in diff
- [ ] Backend, CLI, UI, docs, schema, deploy config, and tests are aligned for this change
- [ ] Branch is refreshed against current `main` if related files/contracts changed upstream
- [ ] Security review completed for touched surfaces: authz, tenant isolation, injection/XSS/prompt-injection, trust boundaries, and privilege escalation
- [ ] Performance and scale impact reviewed for hot paths, traversal, pagination, caching, or repeated full loads
- [ ] Any exception to default-secure behavior is optional, documented, and justified per [docs/CHANGE_GUARDRAILS.md](../docs/CHANGE_GUARDRAILS.md)

## Exceptions
<!-- Leave `None` if not applicable. Otherwise document the relaxation and why it is acceptable. -->

- None
