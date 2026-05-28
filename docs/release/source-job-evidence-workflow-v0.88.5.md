# Source, Job, And Evidence Workflow

This release slice connects the existing control-plane objects into one operator workflow:

- Sources remain the registered scan inputs under `/sources`.
- Schedules remain control-plane scan triggers linked by `scan_config.source_id`.
- Jobs now load hydrated `/v1/jobs?include_details=true` payloads and display the registered source, owner, and evidence state.
- Completed jobs link directly to findings, the security graph, and compliance evidence for the same `job_id`.

Claim boundary: the UI does not invent evidence or score state. It renders persisted `SourceRecord`, `ScanSchedule`, and `JobListItem` fields, including `source_id` when present.

Verification:

```bash
uv run pytest tests/test_api_tenant_isolation.py::test_list_jobs_is_summary_first_and_opt_in_for_hydration -q
cd ui && npm run typecheck
cd ui && npx playwright test e2e/jobs-workflow.spec.ts --project=chromium
```
