# Alpine APK advisory coverage gap

Status: **tracked** — partial fix in [#TBD]; remaining work below.

## Summary

Hands-on container scans show major under-detection on Alpine Linux images compared
with reference scanners. Package extraction (OCI/APK inventory) is correct; the gap
is **advisory coverage and matching** for distro-scoped apk packages.

Example (`alpine:3.14` tarball, 14 apk packages extracted):

| Scanner | Vulns reported |
| --- | ---: |
| agent-bom (pre-fix, stale DB) | 2 |
| Reference scanner (Grype) | 37 |

This is a **P1 accuracy** issue for security buyers evaluating container scanning.

## Root causes (confirmed)

1. **SecDB sync window too narrow** — `sync_alpine_secdb` only ingested `v3.18`–`v3.23`,
   missing EOL-but-common branches such as `v3.14`–`v3.17`.
2. **OSV fallback list matched sync window** — apk packages without `distro_version`
   fell back to the same narrow branch list.
3. **Release keying** — fixed separately in `alpine_release_branch()` (point releases
   like `3.16.9` must map to `v3.16`). Do not regress.
4. **Subpackage matching** — Alpine secdb keys advisories by origin/source package;
   installed subpackages (`musl-utils`, `ssl_client`) must query via `source_package`.

## Shipped in the scan-accuracy PR

- [x] Extend `ALPINE_SECDB_BRANCHES` to `v3.14`–`v3.23` (shared constant in
  `package_utils.py`).
- [x] Align `_ALPINE_OSV_FALLBACKS` with the same branch list.
- [x] Optional `AGENT_BOM_IMAGE_GRYPE_FALLBACK=1` bridge for `agent-bom image --tar`
  (`docker-archive:` target) when native matching under-reports.
- [x] Regression tests for branch constants and release keying.

## Remaining work

- [ ] **DB refresh cadence** — document that existing installs need
  `agent-bom db update` after upgrading to pick up new secdb branches.
- [ ] **Accuracy baseline** — add alpine:3.14 (or fixture tar) to
  `tests/fixtures/accuracy/` with a minimum vuln floor once DB is warm.
- [ ] **Coverage-gap UX** — when apk advisories are sparse for a detected release,
  surface the existing `detect_release_coverage_gaps()` warning in `agent-bom image`
  focused output (not only full `agents` scan).
- [ ] **OSV online fallback** — for offline=false image scans on EOL Alpine branches,
  consider OSV `Alpine:v3.xx` batch lookup when local secdb row count is below threshold.
- [ ] **Benchmark table** — publish reproducible compare script output in
  `docs/PERFORMANCE_BENCHMARKS.md` (no competitor names in marketing copy; script
  may reference tools for internal QA).

## Verification commands

```bash
# After agent-bom db update
agent-bom image --tar /path/to/alpine-3.14.tar -f json | jq '[.[] | .. | objects | select(has("vulnerabilities"))] | length'

# Optional bridge when local DB is stale or branch is sparse
AGENT_BOM_IMAGE_GRYPE_FALLBACK=1 agent-bom image --tar /path/to/alpine-3.14.tar -f json

pytest tests/test_alpine_release_keying.py tests/test_image_grype_tar_fallback.py -q
python scripts/generate_doc_architecture_svgs.py
pytest tests/test_doc_architecture_svgs.py -q
```

## Acceptance criteria

1. `alpine:3.14` tarball scan reports **materially more** than 2 vulnerabilities after
   `db update` on a fresh install (target: within ~20% of Grype on the same tar, acknowledging
   EOL distro variance).
2. `agent-bom db update` ingests secdb rows for `alpine:v3.14` (verify with
   `sqlite3 ~/.agent-bom/vulns.db "select count(*) from affected where ecosystem='alpine:v3.14'"`).
3. Coverage-gap warning appears when advisory row count for a detected release is near zero.
4. No regression on npm/pypi spot-check accuracy or red-team corpus tests.
