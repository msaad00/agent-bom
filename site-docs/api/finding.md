# Finding

Unified finding model for all security findings (vulnerabilities, SAST, compliance, enforcement).

::: agent_bom.finding
    options:
      show_root_heading: true
      members:
        - Finding
        - FindingType
        - FindingSource
        - Asset

## Findings after an incomplete collection

`GET /v1/findings` retains earlier observations when a newer attempt for the same
tenant, source and target explicitly reports incomplete coverage. Retained rows
carry `observation_status: "unreconfirmed"` and `reconfirmation` with the attempt's
`scan_id`, `attempted_at` and bounded `reason_codes`. Their original `scan_id`,
observation timestamps and provenance remain unchanged. Findings actually
observed by the newer attempt carry `observation_status: "observed"`.

Use `?scan_id=<candidate-id>` to inspect only that scan's records. Grouped results
include `unreconfirmed_occurrence_count` and preserve the qualifiers on each
sampled occurrence. The dashboard badges these rows and explains the collection
gap in the finding drawer. Restore the missing collection coverage, then rescan
the same scope before attempting campaign verification.

This fold uses retained scans within the requested time window. Legacy snapshots
without coverage metadata retain their existing replacement behavior; absent
metadata does not establish complete coverage. A complete replacement may remove
a finding from the current list, but list absence alone does not prove a fix,
eliminate alternate paths or establish successful remediation. Verification of
unreconfirmed original campaign members returns `409 unavailable_evidence` with
`retry_state: "awaiting_fresh_scope_evidence"` without changing workflow state.
