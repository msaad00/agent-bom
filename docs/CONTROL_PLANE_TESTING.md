# Control-Plane Testing Matrix

This page describes which operator-facing control-plane flows are covered by
cross-component contract tests today, and which areas are still mostly
unit-tested.

For the security-gate, artifact, and pentest-preparation evidence index, see
[`docs/SECURITY_TESTING_EVIDENCE.md`](SECURITY_TESTING_EVIDENCE.md).

It exists to keep the testing story honest. `agent-bom` has deep unit coverage,
but not every enterprise flow is exercised end-to-end through the same test
shape.

## Contract-Tested Flows

These flows have named tests that cross multiple components instead of only
isolated units:

| Flow | Coverage | Main tests |
|---|---|---|
| Scan result -> persisted graph snapshot -> gateway discovery/policy/audit path | Control-plane contract coverage with real graph persistence and HTTP route exercise | `tests/test_control_plane_contracts.py` |
| Multi-tenant boundaries across control-plane request paths | Tenant isolation and auth-scoped request coverage | `tests/test_gateway_auth_tenant_e2e.py`, `tests/test_api_cross_tenant_matrix.py`, `tests/test_cross_tenant_leakage.py` |
| Store-backed graph API behavior | Route and backend parity for graph traversal, node detail, and compliance views | `tests/test_graph_api.py`, `tests/test_graph_backend.py` |
| Snowflake warehouse-native supported slice | Health/storage contract plus supported schedules/exceptions route wiring | `tests/test_snowflake_backend_contract.py`, `tests/test_snowflake_stores.py` |

## Mostly Unit-Tested Or Partial Flows

These areas have good local coverage, but are not yet exercised as one
end-to-end operator path in CI:

| Area | Current status |
|---|---|
| Remediation / compliance / export after persisted graph ingest | Strong formatter and API tests, but not a full control-plane scenario chained from persisted scan input |
| Backup / restore and migration round-trips | Migration and store tests exist, but not a named disaster-recovery scenario |
| Multi-replica gateway/control-plane reload behavior | Covered by route/store and Helm wiring tests, but not by a distributed multi-process contract test |
| Full signed evidence retrieval after runtime enforcement | Core audit and export paths are covered, but not yet as one named end-to-end control-plane scenario |

## How To Read This Matrix

- "Contract-tested" means the scenario crosses multiple layers such as route,
  store, persistence, tenant scoping, or runtime evaluation.
- "Mostly unit-tested" does not mean untested. It means the repo still relies
  more on focused component tests than on a single cross-component scenario for
  that path.

## Update Rule

If a PR adds or removes a meaningful control-plane contract test, update this
page in the same PR so the documented test story stays aligned with the repo.
