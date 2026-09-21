# Recorded access comparison receipts

`agent_bom.graph.remediation_receipts` defines an internal producer contract for
comparing an exact recorded authorization path with a fresh collection. It does
not expose an HTTP endpoint, change provider grants, or mark a campaign fixed.
Current scan payloads do not supply this contract automatically.

A trusted collector must produce an `AccessCollectionReceipt` alongside each
immutable graph and native `AuthorizationEvidenceBundle`. Persist the receipt,
the comparison request, and their inputs together; then call
`compare_recorded_access(baseline, candidate, request, now=...)`. Store the returned
`AccessComparisonReceipt` as evidence of that comparison, not as current access
state. A subsequent comparison must recheck freshness and content pins.

## Required evidence

Each collection receipt pins the tenant, source connection, exact provider scope,
configuration digest, scan identifier, graph digest and authorization-input
digest. Its timestamps bound a live collection, including the evaluator's
observation and graph creation. A non-empty native required-source contract and
complete receipts for authorization, identity binding, policy conditions,
session context and alternate paths are required. Missing or partial collection
cannot become complete through an empty graph or an empty findings list.

Principal and resource receipts bind graph nodes to native identifiers. Each
traversed identity hop also needs its own complete receipt and a native principal
binding for its destination. An unbound reachable identity is unknown, not an
empty permission set. The request pins the exact baseline edge sequence,
principal, resource, action, plane and grant identifiers. Read and write actions are compared independently.

A removal additionally requires an explicit observed revocation receipt for
every selected grant. A grant disappearing from a payload is insufficient.
Revocation receipts identify the source evidence where the collector observed
the revoked state during the candidate collection; they are not user-authored
scenario operations. Contradictory current grants return unavailable evidence.

The first evaluator supports the existing Azure and GCP authorization bundles.
Other providers, hypothetical scenarios, expired-grant interpretation, and
changes established only by a new deny require their own producer contracts;
this interface does not infer them from labels or graph shape.

## Result boundaries

| Outcome | Meaning |
| --- | --- |
| `recorded_authorization_removed` | The selected grants have explicit revocation evidence, the fresh native evaluation denies the requested action, and no supported recorded alternative remains within complete comparable evidence. |
| `recorded_access_remains` | A supported directed path remains, with an action-specific native allow receipt. `selected_authorization_removed` separately reports whether the selected grants were revoked. |
| `unavailable_evidence` | A pin, coverage, context, timing, revocation, consistency or traversal requirement could not be established. `reason_codes` explains the bounded failure without raw provider diagnostics. |

Every result retains request and collection receipt digests, snapshot IDs, the
comparison method version and all freshness/traversal limits.
`remediation_verified` and `successful_action_proven` are always false. These
results do not establish successful access, exploitation, data loss, business
impact, or the absence of attack routes outside the collected authority scope.
A remaining route is one deterministic shortest recorded witness, not a count of
all possible paths or affected assets.

Traversal covers `authenticates_as`, `assumes`, `member_of`, `can_access` and
`has_permission`. Identity transitions require their own context receipts;
access to a different resource does not imply authority to use its identity.
Identity transitions cannot substitute for the terminal action edge.
Terminal access requires an exact action, principal and resource receipt that
agrees with the native evaluator. Reverse, nontraversable and expired edges do
not establish a route. Missing selected authority, missing materialized allows,
unknown policy conditions, ambiguous receipts and exhausted budgets cannot
produce a removed result.

The default bounds are 2,000 nodes, 10,000 edges or native authorization records,
16 hops, a one-hour candidate age and a one-second comparison deadline. These
are conservative work limits, not production-scale performance claims.

## Trust and persistence

This function is not an untrusted receipt-submission boundary. Its caller must
authorize the tenant and obtain receipts from a trusted collector. SHA-256 pins
detect content changes; they do not authenticate the producer. Do not synthesize
missing coverage, context or revocation fields for historical scans, and do not
reseal a changed historical graph to make its original pin pass.

Provider collection adapters, durable authenticated receipt storage, and
campaign/API/MCP/SDK/UI integration are prerequisites for an operator-facing
verification workflow. Existing proposed-scenario comparisons remain
hypothetical. Existing remediation guards remain in force until a complete
workflow can consume these receipts without inventing evidence.
