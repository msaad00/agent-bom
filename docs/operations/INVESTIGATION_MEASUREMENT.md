# Measure an investigation and rescan

Use this workflow to evaluate a reviewed relationship set and a before/after
change in your own environment. It runs locally against saved evidence, makes no
provider calls, and changes no infrastructure. Retain the inputs privately;
the output contains counts, content hashes and reported durations, not customer
identifiers or source records.

## 1. Define the case and collect the baseline

Choose one tenant, a stable collection scope, the relationships to review, and
an approved change. Agree on positive **and negative** relationship labels with
an operator who can inspect the source system. Record the investigation start
and decision times. Do not derive ground truth solely from the graph being
measured. Retain the source records and approval/change receipt independently.

Retrieve a retained scan through the authenticated
`GET /v1/graph?scan_id={scan_id}&limit=5000` route. Preserve its native
`scan_id`, `tenant_id`, nodes, edges and completeness fields. Select a case that
fits a complete response; node paging and edge limits otherwise produce unknown
absence checks. For larger graphs, an operator can export a full retained
snapshot through the graph-store adapter (`load_graph(...).to_dict()`) from a
private database copy. Keep its completeness receipt unchanged. Do not flatten
partial pages or set completeness flags to hide omissions. A Cytoscape export
is not accepted. The dependency-only `/v1/scan/{job_id}/graph-export` output lacks
collection completeness and cannot establish absent relationships.

From a source checkout:

```bash
uv run python scripts/evaluate_investigation.py prepare \
  --graph before-graph.json --scope-id pilot-scope \
  --collected-at 2026-10-08T13:00:00Z \
  --source-evidence-ref collector:before \
  --collection-complete --output before-evidence.json
```

Use the actual collection time and an opaque reference to the collector's
receipt. `--collection-complete` is an operator declaration: omit it when any
required source failed or coverage is unknown. This flag cannot override an
incomplete native graph. The command prints the content digest for the review.
Output files must be new; an existing artifact is never overwritten.

## 2. Apply the authorized change and rescan

The operator applies the separately approved change using the environment's
normal change process, records its completion time, and repeats the same scan
scope. This evaluator does not authorize or execute changes. Retain the new
scan under a distinct scan ID; preserve the baseline.

Export the second graph and run `prepare` with its collection time, the same
scope ID, a new collector reference and `--output after-evidence.json`.
Missing entities, partial collection and unresolved paging are unknown evidence,
not proof of a removed relationship. Choose checks whose endpoint identities
remain comparable across scans. A version change that creates a different
package node is not an exact-edge comparison; use the component rescan evidence
in [the connected component workflow](../../examples/connected-bom/README.md).

## 3. Review the source evidence

Generate the strict input schema:

```bash
uv run python scripts/evaluate_investigation.py review-schema --output review-schema.json
```

Create `review.json`, using actual timestamps and the digests printed by
`prepare`. This abbreviated example illustrates the shape; its values are
placeholders and must not be used as customer evidence:

```json
{
  "schema_version": "investigation-review.v1",
  "evidence_origin": "customer_observed",
  "tenant_id": "tenant-id-from-both-exports",
  "scope_id": "pilot-scope",
  "reviewer_ref": "reviewer:operator",
  "reviewed_at": "2026-10-08T13:20:00Z",
  "before_digest": "sha256:REPLACE_WITH_BEFORE_DIGEST",
  "after_digest": "sha256:REPLACE_WITH_AFTER_DIGEST",
  "timeline": {
    "investigation_started_at": "2026-10-08T13:01:00Z",
    "decision_at": "2026-10-08T13:05:00Z",
    "change_applied_at": "2026-10-08T13:10:00Z",
    "rescan_started_at": "2026-10-08T13:11:00Z"
  },
  "change_evidence_ref": "change:approved-and-applied",
  "relationships": [
    {"snapshot": "before", "source": "principal-id", "target": "resource-id",
     "relationship": "can_access", "expected": true, "evidence_ref": "source:grant"},
    {"snapshot": "after", "source": "principal-id", "target": "resource-id",
     "relationship": "can_access", "expected": false, "evidence_ref": "source:revocation"}
  ],
  "outcomes": [
    {"check_id": "selected-relationship", "edge": {
      "source": "principal-id", "target": "resource-id", "relationship": "can_access"},
     "before_present": true, "after_present": false, "verification_ref": "collector:after-check"}
  ]
}
```

Use `fixture` for synthetic data. `customer_observed` is an operator declaration,
not authenticated evidence of a customer deployment. Source/reviewer references
bind the review record but the evaluator cannot authenticate their issuers.
Duplicate relationship labels, duplicate outcome edges, cross-tenant/scope
inputs, changed digests and invalid chronology are rejected.

## 4. Produce and interpret the measurement

```bash
uv run python scripts/evaluate_investigation.py measure \
  --before before-evidence.json --after after-evidence.json \
  --review review.json --output measurement.json
```

| Output | Interpretation |
| --- | --- |
| `true_positive`, `false_positive` | Observed relationships reviewed as correct or incorrect |
| `false_negative`, `true_negative` | Reviewed relationships absent from complete, comparable evidence |
| `unknown` | Absence cannot be evaluated because collection, graph coverage or endpoint identity is incomplete |
| `precision`, `recall` | Scores within the reviewed set; unknowns excluded and counted separately |
| `false_discovery_rate` | False positives / reviewed observed relationships |
| `false_positive_rate` | False positives / evaluated negative labels |
| `observed_review_coverage` | Fraction of observed snapshot/relationship pairs that were reviewed |
| `unreviewed_observed` | Observed relationships with no label; never counted as false correlations |
| `reported_investigation_seconds` | Operator-reported decision time minus investigation start; not instrumented UI time |
| `reported_change_to_rescan_seconds` | Operator-reported collection completion minus change completion |
| `outcomes.evidence_supported` | Exact before/after relationship states agree with the recorded check |
| `independently_verified` | Always false: content hashes and operator assertions do not authenticate collectors |

Zero denominators yield `null`, not a perfect score. A successful command means
valid evaluation, not that every check passed. Read `failed`, `unknown`, review
coverage and collection completeness alongside the scores. Comparison is exact
and directed; same labels or reversed endpoints do not match.

An evidence-supported edge removal is not proof of revoked effective access:
alternate grants, policy conditions and runtime outcomes need their own
collector-backed authorization checks. This workflow does not emit a general
remediation-success verdict. Keep independent provider checks and their receipts
with the case, and use the typed authorization comparison contract when that
narrow proof is required. Do not aggregate fixture scores into customer results.
For improvement claims, repeat the same reviewed case and scope, retain every
run including failures, and compare the reported times and outcome counts.
