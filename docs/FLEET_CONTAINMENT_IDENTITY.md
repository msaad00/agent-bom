# Fleet containment identity

Read `GET /v1/fleet` with your deployment's authenticated API credentials and
retain the target's `agent_id`. Use that exact ID in
`POST /v1/fleet/{agent_id}/quarantine`. The resulting gateway policy binds that
fleet ID inside the request's tenant. The policy's own ID is deterministic
from both tenant and fleet ID, so repeated containment and later release target
the same policy even after a display-name change.

Provision the caller's authenticated workload identity with that fleet
`agent_id`. Gateway lookup is an exact, case-sensitive tenant/ID lookup; display
names and canonical inventory aliases do not resolve a workload for containment.
A self-declared name or tag is not authentication. Existing deployments whose
token mappings contain display names must update those mappings to fleet IDs
before relying on fleet containment.

Name-bound policies created by older versions are not automatically reassigned
or disabled: their intended subject cannot be established from a name. Inspect
and explicitly replace them through the authenticated policy API. Releasing an
ID-bound quarantine only disables that agent's deterministic policy, not another
agent's policy or a legacy policy with a similar label.

This change hardens identity selection; it does not add transactional intent,
an outbox, enforcement acknowledgements, or cancellation of in-flight upstream
work. Existing gateway modes remain: `enforce` blocks known quarantined callers,
`warn` reports, and `off` leaves fleet state advisory. Fleet lookup errors fail
closed in `enforce` mode with `fleet_lookup_unavailable`; `warn` reports the
degraded decision. An unknown ID has no fleet quarantine decision; this check
does not require every caller to be enrolled. Enforce caller admission through
the gateway authentication and policy configuration. Do not treat an API state
change as proof of fleet-wide enforcement.
