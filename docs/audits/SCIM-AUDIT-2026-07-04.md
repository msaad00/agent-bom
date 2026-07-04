# SCIM 2.0 audit ledger (2026-07-04)

**Scope:** Hands-on live endpoint exercise + code review on `origin/main @ 62d217fca`.
**Policy:** User provisioning credential model and tenant isolation are product-critical; group sync and strict SCIM envelopes are IdP-conformance blockers.

---

## Ratings (1–10)

| Dimension | Score | Note |
|---|---|---|
| Provisioning credential model | 9 | Dedicated `scim_bearer`; normal API keys rejected on `/scim/v2/*` |
| Tenant isolation | 9 | Token-bound tenant; payload `tenant_id` ignored; cross-tenant IDOR not observed |
| User provisioning (Okta/Entra user sync) | 8 | Create, filter, PATCH `active`, DELETE, 409, pagination cap |
| Group provisioning (Push Groups) | 4 | Member PATCH add/remove corrupts membership (**F1**) |
| Spec compliance (errors, PUT, discovery) | 6 | Bulk uses SCIM Error; single-request errors do not (**F4**) |
| Deprovisioning completeness | 6 | SSO/session overlay works when subject matches; API keys survive (**F3**) |

---

## Verified working (live + tests)

| Area | Evidence |
|---|---|
| SCIM bearer vs API key separation | 401 without/wrong token; 200 with valid bearer; API key rejected |
| Discovery | `ServiceProviderConfig`, `ResourceTypes`, `Schemas` → 200 |
| Users CRUD | 201 create, 409 duplicate (incl. deactivated), DELETE → 204 |
| Filtering | Allowlist parser; injection-style filter → 400, not SQL |
| PATCH users | Path-based and Entra whole-object replace |
| Pagination | `count` capped 500; `count=0` spec-correct |
| Cross-tenant isolation | Two tokens: tenant B sees 0 users from A; GET/PATCH/PUT/DELETE by A's id → 404 |
| Multi-replica safety | Misconfigured multi-replica without Postgres → fail-closed 503 |
| Runtime deprovision (SSO path) | `middleware.py` + `resolve_scim_user_role()` re-check `active` per request |

---

## Findings (code-validated)

| ID | Priority | Finding | Location | GitHub |
|---|---|---|---|---|
| **F1** | **P1 / HIGH** | Group `PatchOp` `remove` for one member clears **all** members; `add` **replaces** list instead of appending | `routes/scim.py` `_apply_group_patch` L241–246 | **#3533** |
| **F2** | P2 / MED | Client-supplied `id` on POST overwrites existing user (within-tenant data loss) | `_user_from_payload` L98; `put_user` upsert | **#3534** |
| **F3** | P2 / MED | Deprovision does not revoke long-lived API keys; no-op if OIDC sub never matches SCIM fields | `deactivate_user`; `describe_scim_posture` deprovisioning_boundary | **#3535** |
| **F4** | P2 / MED | Non-bulk errors use generic JSON envelope, not `urn:ietf:params:scim:api:messages:2.0:Error` + `application/scim+json` | Global exception handler; `_scim_error_response` only used in Bulk | **#3536** |
| **F5** | P3 / LOW | PUT behaves as merge, not RFC 7644 full replace | `_user_from_payload(..., existing=)` | **#3537** |
| **F6** | P3 / LOW | No `/Schemas/{id}` or `/ResourceTypes/{id}` discovery by id | `routes/scim.py` | **#3537** |
| **F7** | P3 / LOW | List materializes full tenant in memory (bounded 500/page — no single-request DoS) | `list_users` / `list_groups` | **#3537** |
| **F8** | P3 / INFO | Group membership stored but does not drive authorization roles | groups inert for RBAC | **#3537** |

Test regression coverage: **#3538**

### F1 reproduction (confirmed on `main`)

```python
# Group with members [A, B]; PATCH add member C → members == [C] only (A,B lost)
# PATCH remove members[value eq "A"] → members == [] (all removed)
```

Existing test `test_scim_group_lifecycle_accepts_common_idp_members` asserts the buggy remove-all behavior; it should be updated when F1 is fixed.

### F2 reproduction (confirmed on `main`)

```python
POST /Users {"userName": "victim@example.com"}  → id = UUID-1
POST /Users {"userName": "attacker@example.com", "id": "UUID-1"}
GET  /Users/UUID-1 → userName == "attacker@example.com"  # overwrites victim
```

---

## Test gaps

| Gap | Action |
|---|---|
| Cross-tenant PATCH/DELETE/PUT | Live-passed; add regression tests (**#3538**) |
| Group member add/remove semantics | Add tests that fail today; fix with **#3533** |
| SSO session revoke on deprovision | Integration test with live OIDC session (harness gap) |

---

## Bottom line

User provisioning for Okta/Entra **user sync** is production-grade on credential model and tenant isolation. **Group Push / Entra group sync will fail conformance** until **F1** is fixed. Treat **F3** explicitly in buyer docs until API-key revocation on deprovision ships or is accepted as out of scope.

---

_Update this ledger when SCIM fix PRs merge._
