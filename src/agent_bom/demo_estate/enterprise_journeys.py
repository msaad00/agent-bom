"""Emit multi-source traces — the evidence that makes a correlation a correlation.

The estate used to give every observation its own ``trace_id``. Grouping by trace
then produced one "correlation" per event: 6,148 rows of which 6,145 were a
single event grouped with itself, and the surface headed *cross-vendor
correlations* honestly reported 3. The count looked enormous and demonstrated
nothing, which is the worst possible combination for a demo.

A journey here is one actor, one trace id, and an ordered walk across vendors:
a workflow federates into a cloud role, the role reaches a Kubernetes workload,
the workload calls an MCP tool, the tool queries the warehouse, and the result is
handed to a model — six sources, six systems, one story. The correlation layer
does not need to be told any of this; it groups by trace exactly as it always
has, and the chain falls out.

Every choice — which assets, which actor, when, and whether the egress was
blocked — is derived from the identity of the journey, so the estate is
byte-identical on every run.
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta

from agent_bom.demo_estate.enterprise import (
    ENTERPRISE_SCHEMA_VERSION,
    EstateAsset,
    EstateStage,
    EvidenceProvenance,
    EvidenceSource,
    RawObservation,
)
from agent_bom.demo_estate.enterprise_ai import AI_LANE_TAG, stable_index

_TENANT_DOMAIN = "northstar.example"
_PLACEHOLDER_HASH = "0" * 64

# The workforce the whole estate shares. Principals are deliberately NOT
# per-provider: an identity that only ever appears in one cloud can never
# produce a cross-vendor session, and an estate where nobody works across
# clouds cannot demonstrate correlation across them.
_HUMAN_ROLES: tuple[str, ...] = (
    "a.okafor",
    "l.mendes",
    "s.raghavan",
    "j.novak",
    "m.delacruz",
    "t.bergstrom",
    "r.iyer",
    "c.whitfield",
)
_WORKLOAD_PRINCIPALS: tuple[str, ...] = (
    "svc-claims-etl",
    "svc-care-gap",
    "svc-feature-store",
    "svc-model-router",
    "svc-eligibility",
    "svc-appeals",
)
_AGENT_PRINCIPALS: tuple[str, ...] = (
    "agent:member-copilot",
    "agent:claims-triage",
    "agent:prior-auth-reviewer",
    "agent:care-gap-outreach",
)


def principal_pool() -> tuple[str, ...]:
    """The estate's actors, in one stable order.

    Shared by the per-asset activity generator and by journeys so a principal
    seen deploying in CI is the same string seen querying the warehouse — which
    is the join the whole correlation rests on.
    """
    return (
        *(f"{name}@{_TENANT_DOMAIN}" for name in _HUMAN_ROLES),
        *(f"{name}@{_TENANT_DOMAIN}" for name in _WORKLOAD_PRINCIPALS),
        *_AGENT_PRINCIPALS,
    )


@dataclass(frozen=True, slots=True)
class _Pools:
    """Assets grouped by the role they can play in a journey."""

    workflows: tuple[EstateAsset, ...]
    identities: tuple[EstateAsset, ...]
    workloads: tuple[EstateAsset, ...]
    tools: tuple[EstateAsset, ...]
    tables: tuple[EstateAsset, ...]
    models: tuple[EstateAsset, ...]
    ai_services: tuple[EstateAsset, ...]

    @property
    def complete(self) -> bool:
        return all((self.workflows, self.identities, self.workloads, self.tools, self.tables, self.models))


_IDENTITY_TYPES = frozenset({"iam_role", "service_principal", "service_account", "role"})
_AI_SERVICE_TYPES = frozenset(
    {
        "bedrock_agent",
        "sagemaker_endpoint",
        "vertex_endpoint",
        "vertex_agent",
        "azure_openai_deployment",
        "cognitive_services_account",
        "cortex_function",
        "cortex_search_service",
        "spcs_service",
        "gemini_api",
    }
)
_MODEL_TYPES = frozenset({"hosted_model", "model_artifact", "foundation_model", "vertex_model", "sagemaker_model"})


def _pools(assets: Sequence[EstateAsset]) -> _Pools:
    def pick(predicate) -> tuple[EstateAsset, ...]:
        return tuple(sorted((a for a in assets if predicate(a)), key=lambda a: a.asset_id))

    return _Pools(
        workflows=pick(lambda a: a.resource_type == "workflow"),
        identities=pick(lambda a: a.resource_type in _IDENTITY_TYPES),
        workloads=pick(lambda a: a.resource_type == "deployment"),
        tools=pick(lambda a: a.resource_type == "tool"),
        tables=pick(lambda a: a.resource_type in {"table", "database"} and a.provider == "snowflake"),
        models=pick(lambda a: a.resource_type in _MODEL_TYPES),
        ai_services=pick(lambda a: a.resource_type in _AI_SERVICE_TYPES),
    )


# Which cloud audit log speaks for the identity a journey federates into.
_AUDIT_SOURCE: dict[str, EvidenceSource] = {
    "aws": EvidenceSource.AWS_CLOUDTRAIL,
    "azure": EvidenceSource.AZURE_ACTIVITY,
    "gcp": EvidenceSource.GCP_AUDIT,
    "snowflake": EvidenceSource.SNOWFLAKE_ACCESS_HISTORY,
}
_FEDERATION_EVENT: dict[str, str] = {
    "aws": "AssumeRoleWithWebIdentity",
    "azure": "Microsoft.Authorization/roleAssignments/write",
    "gcp": "iam.serviceAccounts.getAccessToken",
    "snowflake": "GRANT_ROLE",
}
_AI_INVOKE_EVENT: dict[str, str] = {
    "aws": "bedrock:InvokeModelWithResponseStream",
    "azure": "Microsoft.CognitiveServices/accounts/deployments/action",
    "gcp": "aiplatform.endpoints.predict",
    "snowflake": "CORTEX_COMPLETE",
}


def _seal(observation: RawObservation) -> RawObservation:
    """Stamp the evidence hash with the estate's own hasher, never a second one."""
    from agent_bom.demo_estate.enterprise import _observation_hash

    digest = _observation_hash(observation.model_dump(mode="json", exclude={"provenance"}))
    return observation.model_copy(update={"provenance": observation.provenance.model_copy(update={"evidence_hash": digest})})


def _observation(
    *,
    event_id: str,
    source: EvidenceSource,
    event_type: str,
    observed_at: datetime,
    actor_id: str,
    resource_ids: tuple[str, ...],
    trace_id: str,
    payload: dict[str, object],
    tenant_id: str,
    run_id: str,
) -> RawObservation:
    return _seal(
        RawObservation(
            event_id=event_id,
            stage=EstateStage.CURRENT,
            source=source,
            event_type=event_type,
            observed_at=observed_at,
            actor_id=actor_id,
            resource_ids=resource_ids,
            trace_id=trace_id,
            raw_payload=payload,
            provenance=EvidenceProvenance(
                source=source,
                source_event_id=event_id,
                observed_at=observed_at,
                run_id=run_id,
                tenant_id=tenant_id,
                evidence_hash=_PLACEHOLDER_HASH,
                schema_version=ENTERPRISE_SCHEMA_VERSION,
            ),
        )
    )


def build_journeys(
    assets: Sequence[EstateAsset],
    *,
    tenant_id: str,
    count: int,
    epoch: datetime,
    window_days: int = 28,
) -> tuple[RawObservation, ...]:
    """Emit ``count`` multi-source traces across the estate's own assets.

    A journey never invents a resource: every hop is an asset the caller already
    inventoried, so the contract's own validator — events reference known assets
    — is what proves the chain is joinable rather than a separate assertion.
    """
    pools = _pools(assets)
    if not pools.complete or count <= 0:
        return ()

    principals = principal_pool()
    observations: list[RawObservation] = []

    for index in range(count):
        journey_id = f"journey-{index:05d}"
        # Tenant-independent for the same reason as ``session_trace_id``: the
        # estate is one estate, whoever seeds it.
        seed = stable_index(journey_id)
        actor = principals[seed % len(principals)]
        trace_id = hashlib.sha256(f"journey|{journey_id}".encode()).hexdigest()[:32]
        run_id = "demo-run-journey"

        workflow = pools.workflows[seed % len(pools.workflows)]
        repository = workflow.tags.get("repository", "")
        identity = pools.identities[(seed // 3) % len(pools.identities)]
        workload = pools.workloads[(seed // 7) % len(pools.workloads)]
        tool = pools.tools[(seed // 11) % len(pools.tools)]
        table = pools.tables[(seed // 13) % len(pools.tables)]
        model = pools.models[(seed // 17) % len(pools.models)]
        ai_service = pools.ai_services[(seed // 19) % len(pools.ai_services)] if pools.ai_services else None
        image = workload.tags.get("container_image", "")
        cluster = workload.tags.get("cluster", "")
        mcp_server = tool.tags.get("mcp_server", "")

        audit_source = _AUDIT_SOURCE.get(identity.provider, EvidenceSource.AWS_CLOUDTRAIL)
        # Steps run seconds to a couple of minutes apart, inside a window that
        # spreads journeys across the collection period rather than stacking
        # them on one timestamp.
        start = epoch + timedelta(minutes=(seed // 23) % (window_days * 24 * 60))
        step = timedelta(seconds=7 + (seed % 53))

        # Was the egress blocked? Read from the journey's own policy decision
        # below, never assumed: an estate where every attempt is blocked cannot
        # show that the policy is evaluated rather than asserted.
        blocked = seed % 3 != 0

        def event(
            offset: int,
            source: EvidenceSource,
            event_type: str,
            resource_ids: tuple[str, ...],
            payload: dict[str, object],
        ) -> None:
            resources = tuple(dict.fromkeys(r for r in resource_ids if r))
            if not resources:
                return
            observations.append(
                _observation(
                    event_id=f"evtj-{hashlib.sha256(f'{journey_id}:{offset}'.encode()).hexdigest()[:20]}",
                    source=source,
                    event_type=event_type,
                    observed_at=start + step * offset,
                    actor_id=actor,
                    resource_ids=resources,
                    trace_id=trace_id,
                    payload=payload,
                    tenant_id=tenant_id,
                    run_id=run_id,
                )
            )

        event(
            0,
            EvidenceSource.GITHUB_ACTIONS,
            "workflow_run.completed",
            (repository, workflow.asset_id, image),
            {
                "action": "completed",
                "workflow": workflow.display_name,
                "conclusion": "success",
                "head_branch": "main" if seed % 4 else f"release/{seed % 12}",
                "oidcUnconstrained": workflow.tags.get("oidc_unconstrained") == "true",
            },
        )
        event(
            1,
            audit_source,
            _FEDERATION_EVENT.get(identity.provider, "AssumeRole"),
            (workflow.asset_id, identity.asset_id),
            {
                "eventName": _FEDERATION_EVENT.get(identity.provider, "AssumeRole"),
                "accountScope": identity.account_scope,
                "region": identity.region,
                "environment": identity.environment,
                "readOnly": False,
                "overPermissive": identity.tags.get("over_permissive") == "true",
            },
        )
        event(
            2,
            EvidenceSource.KUBERNETES_AUDIT,
            "pods/exec.create" if seed % 5 == 0 else "deployments.update",
            (cluster, workload.asset_id, image, identity.asset_id),
            {
                "verb": "create" if seed % 5 == 0 else "update",
                "namespace": workload.tags.get("environment", workload.environment),
                "responseStatus": {"code": 201},
                "privileged": workload.tags.get("privileged") == "true",
            },
        )
        event(
            3,
            EvidenceSource.MCP_GATEWAY,
            "tools/call",
            (workload.asset_id, mcp_server, tool.asset_id, table.asset_id),
            {
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {"name": tool.display_name, "bind_count": 1 + (seed % 3)},
                "server": mcp_server,
                "agent_id": workload.display_name,
                "decision": "allow",
                "policy_id": "mcp-prod-readonly-v3",
                "latency_ms": 11 + (seed % 40),
            },
        )
        event(
            4,
            EvidenceSource.SNOWFLAKE_ACCESS_HISTORY,
            "ACCESS_HISTORY_QUERY_HISTORY_JOIN",
            (tool.asset_id, table.asset_id),
            {
                "query_type": "SELECT",
                "objects_accessed": [table.native_id],
                "rows_produced": 40 + (seed % 4000),
                "classifications": list(table.data_classifications),
            },
        )
        if ai_service is not None:
            event(
                5,
                _AUDIT_SOURCE.get(ai_service.provider, audit_source),
                _AI_INVOKE_EVENT.get(ai_service.provider, "InvokeModel"),
                (ai_service.asset_id, table.asset_id, ai_service.tags.get("uses_identity", "")),
                {
                    "eventName": _AI_INVOKE_EVENT.get(ai_service.provider, "InvokeModel"),
                    "accountScope": ai_service.account_scope,
                    "region": ai_service.region,
                    "environment": ai_service.environment,
                    "modelFamily": ai_service.tags.get("model_family", ""),
                    "readOnly": True,
                },
            )
        event(
            6,
            EvidenceSource.OTEL_LLM,
            "gen_ai.chat",
            (workload.asset_id, model.asset_id, table.asset_id),
            {
                "span_id": hashlib.sha256(journey_id.encode()).hexdigest()[:16],
                "name": f"chat {model.display_name}",
                "kind": "CLIENT",
                "status": {
                    "code": "ERROR" if blocked else "OK",
                    "message": "blocked by data handling policy" if blocked else "completed",
                },
                "attributes": {
                    "gen_ai.provider.name": model.provider,
                    "gen_ai.request.model": model.display_name,
                    "gen_ai.operation.name": "chat",
                    "gen_ai.usage.input_tokens": 120 + (seed % 3000),
                    "agent_bom.decision": "block" if blocked else "allow",
                    "agent_bom.policy_id": "phi-egress-deny-v5",
                    "agent_bom.classifications": list(table.data_classifications),
                },
            },
        )
    return tuple(observations)


# A session is one principal's activity inside one window. Six hours, not a day:
# a day-long window put seventeen events and up to twenty-six assets into a
# single "path", which is not a path, it is a shift roster. Six hours yields
# sessions of a handful of events — small enough that the assets in one plausibly
# relate, large enough to span more than one system.
SESSION_WINDOW_HOURS = 6


def session_trace_id(actor_id: str, observed_at: datetime, tenant_id: str) -> str:
    """Group one principal's activity into a bounded session trace.

    The alternative — a trace id per event — is what produced six thousand
    single-event "correlations". A session is a real grouping unit: the same
    identity, the same window, whatever systems it touched. It is deliberately
    NOT presented as a causal chain; ``_correlation_kind`` labels it
    ``identity_session`` so nothing reads more into it than the evidence shows.
    """
    bucket = observed_at.hour // SESSION_WINDOW_HOURS
    window = f"{observed_at.strftime('%Y-%m-%d')}T{bucket:02d}"
    # ``tenant_id`` is deliberately NOT in the digest. Every tenant seeding the
    # demo must get a byte-identical estate — that invariant is what makes
    # ``test_two_tenants_holding_identical_finding_ids_both_persist`` a valid
    # probe for a dedupe key that omits the tenant. Mixing the tenant in here
    # gave each one a different trace ordering, which changed which correlation
    # claimed each asset and therefore which findings the estate produced at
    # all: two tenants, 2,290 and 2,309 findings, from one generator. Tenancy
    # lives on the provenance and in ``correlation_id``, where it is enforced.
    del tenant_id
    return hashlib.sha256(f"session|{actor_id}|{window}".encode()).hexdigest()[:32]


def actor_for(asset: EstateAsset, occurrence: int) -> str:
    """Pick the principal that acted on ``asset`` — from the shared pool.

    Deriving the actor from the asset rather than from its provider is what lets
    one identity appear in CloudTrail on Monday and in Snowflake access history
    the same afternoon, which is the only way a session can span vendors.
    """
    principals = principal_pool()
    lane = asset.tags.get(AI_LANE_TAG)
    seed = stable_index(asset.asset_id, str(occurrence), lane or "cloud")
    return principals[seed % len(principals)]


__all__ = [
    "actor_for",
    "build_journeys",
    "principal_pool",
    "session_trace_id",
]
