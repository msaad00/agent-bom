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

## Breaking changes
- [ ] None
- [ ] Yes — describe migration path below

## Checklist
- [ ] Version bumped if this is a release PR (`scripts/bump-version.py`)
- [ ] Docs/diagrams updated if features changed (`ARCHITECTURE.md`, `README.md`, SVGs)
- [ ] No secrets, credentials, or personally identifiable data in diff
