"""Typed Python client for the agent-bom control-plane API."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, TypeAlias
from urllib.parse import quote

import httpx

JsonValue: TypeAlias = str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
JsonObject: TypeAlias = dict[str, JsonValue]
QueryValue: TypeAlias = str | int | float | bool | None


class AgentBomApiError(RuntimeError):
    """Raised when the control-plane API returns a non-success status."""

    def __init__(self, message: str, *, status_code: int, body: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class AgentBomClient:
    """Synchronous control-plane client for agent-bom.

    The client is intentionally small and hand-written so the Python package can
    cover the stable API primitives without adding code generation to the
    release path.
    """

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str | None = None,
        bearer_token: str | None = None,
        tenant_id: str | None = None,
        timeout: float = 30.0,
        default_headers: Mapping[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        client: httpx.Client | None = None,
    ) -> None:
        if not base_url.strip():
            raise ValueError("base_url is required")
        if api_key and bearer_token:
            raise ValueError("configure either api_key or bearer_token, not both")
        if client is not None and transport is not None:
            raise ValueError("configure either client or transport, not both")

        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.bearer_token = bearer_token
        self.tenant_id = tenant_id
        self.default_headers = dict(default_headers or {})
        self._owns_client = client is None
        self._client = client or httpx.Client(timeout=timeout, transport=transport)

    def close(self) -> None:
        """Close the underlying HTTP client."""

        if self._owns_client:
            self._client.close()

    def __enter__(self) -> AgentBomClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def health(self) -> JsonObject:
        """Return the control-plane health envelope."""

        return self._request("GET", "/health")

    def exposure_paths(
        self,
        *,
        scan_id: str | None = None,
        limit: int | None = None,
        min_risk: float | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """List graph exposure paths for the request tenant."""

        return self._request(
            "GET",
            "/v1/graph/exposure-paths",
            params=_strip_query_none(
                {
                    "tenant_id": tenant_id or self.tenant_id,
                    "scan_id": scan_id,
                    "limit": limit,
                    "min_risk": min_risk,
                }
            ),
        )

    def attack_paths(
        self,
        *,
        scan_id: str | None = None,
        offset: int | None = None,
        limit: int | None = None,
    ) -> JsonObject:
        """List ranked graph attack paths for the request tenant."""

        return self._request(
            "GET",
            "/v1/graph/attack-paths",
            params=_strip_query_none(
                {
                    "scan_id": scan_id,
                    "offset": offset,
                    "limit": limit,
                }
            ),
        )

    def create_graph_correlation(
        self,
        *,
        name: str,
        scan_ids: Sequence[str],
        max_age_hours: int,
        allow_stale: bool = False,
        idempotency_key: str,
    ) -> JsonObject:
        """Start a bounded correlation over immutable graph snapshots."""

        return self._request(
            "POST",
            "/v1/graph/correlations",
            json={
                "name": name,
                "scan_ids": list(scan_ids),
                "max_age_hours": max_age_hours,
                "allow_stale": allow_stale,
            },
            extra_headers={"Idempotency-Key": idempotency_key},
        )

    def graph_correlation(self, correlation_id: str) -> JsonObject:
        """Read one tenant-scoped graph correlation run."""

        return self._request("GET", f"/v1/graph/correlations/{_quote_path(correlation_id)}")

    def list_graph_correlations(self, *, limit: int = 50) -> JsonObject:
        """List recent tenant-scoped graph correlation runs."""

        return self._request("GET", "/v1/graph/correlations", params={"limit": limit})

    def list_campaigns(self) -> JsonObject:
        """List risk/remediation campaigns for the request tenant."""

        return self._request("GET", "/v1/campaigns")

    def campaign_verification_queue(self, *, cursor: str | None = None, limit: int = 100) -> JsonObject:
        """List one bounded page of inactive campaigns awaiting verification."""

        return self._request(
            "GET",
            "/v1/campaigns/verification-queue",
            params=_strip_query_none({"cursor": cursor, "limit": limit}),
        )

    def update_campaign(
        self,
        campaign_id: str,
        *,
        version: int,
        owner: str | None = None,
        sla_due_at: str | None = None,
        state: str | None = None,
    ) -> JsonObject:
        """Assign a campaign owner/SLA/state using optimistic concurrency."""

        return self._request(
            "PATCH",
            f"/v1/campaigns/{_quote_path(campaign_id)}",
            json=_strip_none({"version": version, "owner": owner, "sla_due_at": sla_due_at, "state": state}),
        )

    def verify_campaign(self, campaign_id: str, *, version: int, idempotency_key: str = "") -> JsonObject:
        """Verify a campaign against the current findings spine (optimistic lock)."""

        return self._request(
            "POST",
            f"/v1/campaigns/{_quote_path(campaign_id)}/verify",
            json={"version": version},
            extra_headers={"Idempotency-Key": idempotency_key} if idempotency_key else None,
        )

    def create_campaign_tickets(
        self,
        campaign_id: str,
        *,
        connection_id: str,
        project: str = "",
        issue_type: str = "",
        cursor: str | None = None,
        limit: int = 25,
    ) -> JsonObject:
        """Create one bounded page of tickets for campaign findings."""

        return self._request(
            "POST",
            f"/v1/campaigns/{_quote_path(campaign_id)}/tickets",
            json=_strip_none(
                {
                    "connection_id": connection_id,
                    "project": project,
                    "issue_type": issue_type,
                    "cursor": cursor,
                    "limit": limit,
                }
            ),
        )

    def sync_campaign_tickets(self, campaign_id: str, *, cursor: str | None = None, limit: int = 25) -> JsonObject:
        """Sync one bounded page of the campaign's linked tickets."""

        return self._request(
            "POST",
            f"/v1/campaigns/{_quote_path(campaign_id)}/tickets/sync",
            params=_strip_query_none({"cursor": cursor, "limit": limit}),
        )

    def compliance_framework(self, framework: str) -> JsonObject:
        """Evaluate a single compliance framework's pass/fail posture."""

        return self._request("GET", f"/v1/compliance/{_quote_path(framework)}")

    # ── Ticketing (connect-once ITSM) ───────────────────────────────────────
    def list_tickets(self) -> JsonObject:
        """List the tenant's filed finding→ticket links."""

        return self._request("GET", "/v1/ticketing/tickets")

    def create_ticket(
        self,
        *,
        finding: Mapping[str, JsonValue],
        connection_id: str = "",
        project: str = "",
        finding_id: str = "",
        issue_type: str = "",
        source_url: str = "",
    ) -> JsonObject:
        """File an ITSM ticket for a finding through a stored connection.

        Carries no credential or base URL: auth and endpoint are resolved from
        the stored, encrypted ticketing connection (connect-once).
        """

        return self._request(
            "POST",
            "/v1/ticketing/tickets",
            json=_strip_none(
                {
                    "finding": dict(finding),
                    "connection_id": connection_id,
                    "project": project,
                    "finding_id": finding_id,
                    "issue_type": issue_type,
                    "source_url": source_url,
                }
            ),
        )

    def sync_ticket(self, ticket_id: str) -> JsonObject:
        """Refresh a filed ticket's status from its ITSM through the connection."""

        return self._request("POST", f"/v1/ticketing/tickets/{_quote_path(ticket_id)}/sync")

    # ── Scheduled findings exports (connect-once destinations) ──────────────
    def list_export_destinations(self) -> list[JsonObject]:
        """List the tenant's connect-once export destinations."""

        return self._request_list("GET", "/v1/exports/destinations")

    def create_export_destination(
        self,
        *,
        kind: str,
        display_name: str,
        config: Mapping[str, JsonValue] | None = None,
    ) -> JsonObject:
        """Create a connect-once export destination (no per-action credential).

        Only non-secret ``config`` is sent; a secret-bearing destination
        (e.g. Snowflake) is provisioned through the connect-once API/hub, not by
        passing a credential to this command.
        """

        return self._request(
            "POST",
            "/v1/exports/destinations",
            json={"kind": kind, "display_name": display_name, "config": dict(config or {})},
        )

    def run_export_destination(self, destination_id: str) -> JsonObject:
        """Fire a one-off findings export to a stored destination now."""

        return self._request("POST", f"/v1/exports/destinations/{_quote_path(destination_id)}/run")

    def list_export_schedules(self) -> list[JsonObject]:
        """List the tenant's export schedules."""

        return self._request_list("GET", "/v1/exports/schedules")

    def create_export_schedule(
        self,
        *,
        name: str,
        cron_expression: str,
        destination_id: str,
        sort: str = "effective_reach",
        severity: str | None = None,
        since_days: int | None = None,
        enabled: bool = True,
    ) -> JsonObject:
        """Create a cron export schedule bound to a stored destination."""

        return self._request(
            "POST",
            "/v1/exports/schedules",
            json=_strip_none(
                {
                    "name": name,
                    "cron_expression": cron_expression,
                    "destination_id": destination_id,
                    "sort": sort,
                    "severity": severity,
                    "since_days": since_days,
                    "enabled": enabled,
                }
            ),
        )

    def should_i_deploy(
        self,
        candidate: str | Mapping[str, JsonValue],
        *,
        block_risk: int | None = None,
        context: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Ask the graph policy engine whether a candidate should deploy."""

        return self._request(
            "POST",
            "/v1/graph/should-i-deploy",
            json=_strip_none(
                {
                    "candidate": candidate,
                    "tenant_id": tenant_id or self.tenant_id,
                    "block_risk": block_risk,
                    "context": dict(context) if context is not None else None,
                }
            ),
        )

    def list_findings(
        self,
        *,
        severity: str | None = None,
        sort: str = "effective_reach",
        limit: int = 500,
        offset: int = 0,
        framework: str | None = None,
        control: str | None = None,
        scan_id: str | None = None,
        query: str | None = None,
        domain: str | None = None,
        provider: str | None = None,
        account: str | None = None,
        environment: str | None = None,
        owner: str | None = None,
        sla: str | None = None,
        finding_class: str | None = None,
        status: str | None = None,
        kev: bool | None = None,
        window_days: int | None = None,
        cursor: str | None = None,
    ) -> JsonObject:
        """List normalized findings from scan jobs and bulk ingests.

        ``framework`` / ``control`` are the compliance drill-through filters
        (epic #4790): a framework section id (e.g. ``soc2`` / ``nist-csf``) and,
        optionally, a control code that narrows within it.
        """

        return self._request(
            "GET",
            "/v1/findings",
            params=_strip_query_none(
                {
                    "severity": severity,
                    "sort": sort,
                    "limit": limit,
                    "offset": offset,
                    "framework": framework,
                    "control": control,
                    "scan_id": scan_id,
                    "q": query,
                    "domain": domain,
                    "provider": provider,
                    "account": account,
                    "environment": environment,
                    "owner": owner,
                    "sla": sla,
                    "finding_class": finding_class,
                    "status": status,
                    "kev": kev,
                    "window_days": window_days,
                    "cursor": cursor,
                }
            ),
        )

    def list_finding_triage(
        self,
        *,
        queue_state: str | None = None,
        decision: str | None = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> JsonObject:
        """List finding triage queue items for the request tenant."""

        return self._request(
            "GET",
            "/v1/findings/triage",
            params=_strip_query_none(
                {
                    "queue_state": queue_state,
                    "decision": decision,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    def create_finding_triage(
        self,
        vulnerability_id: str,
        *,
        package: str = "*",
        server_name: str = "",
        assignee: str = "",
        queue_state: str = "open",
        decision: str = "under_investigation",
        justification: str | None = None,
        decision_reason: str = "",
        expires_at: str = "",
    ) -> JsonObject:
        """Create a finding triage queue item."""

        return self._request(
            "POST",
            "/v1/findings/triage",
            json=_strip_none(
                {
                    "vulnerability_id": vulnerability_id,
                    "package": package,
                    "server_name": server_name,
                    "assignee": assignee,
                    "queue_state": queue_state,
                    "decision": decision,
                    "justification": justification,
                    "decision_reason": decision_reason,
                    "expires_at": expires_at,
                }
            ),
        )

    def update_finding_triage_decision(
        self,
        triage_id: str,
        *,
        decision: str,
        justification: str | None = None,
        decision_reason: str = "",
        assignee: str | None = None,
        expires_at: str | None = None,
    ) -> JsonObject:
        """Record a decision for a finding triage queue item."""

        return self._request(
            "PUT",
            f"/v1/findings/triage/{_quote_path(triage_id)}/decision",
            json=_strip_none(
                {
                    "decision": decision,
                    "justification": justification,
                    "decision_reason": decision_reason,
                    "assignee": assignee,
                    "expires_at": expires_at,
                }
            ),
        )

    def export_finding_triage_vex(
        self,
        *,
        assignee: str | None = None,
        package: str | None = None,
        vulnerability_id: str | None = None,
        server_name: str | None = None,
        scope: str | None = None,
        query: str | None = None,
        severity: str | None = None,
        scan_id: str | None = None,
        provider: str | None = None,
        account: str | None = None,
        environment: str | None = None,
        domain: str | None = None,
        window_days: int | None = None,
        status: str | None = None,
        finding_class: str | None = None,
        kev: bool | None = None,
        framework: str | None = None,
        control: str | None = None,
        owner: str | None = None,
        sla: str | None = None,
    ) -> JsonObject:
        """Export OpenVEX for eligible triage decisions, optionally scoped to a finding view."""

        return self._request(
            "GET",
            "/v1/findings/triage/vex",
            params=_strip_query_none(
                {
                    "assignee": assignee,
                    "package": package,
                    "vulnerability_id": vulnerability_id,
                    "server_name": server_name,
                    "scope": scope,
                    "q": query,
                    "severity": severity,
                    "scan_id": scan_id,
                    "provider": provider,
                    "account": account,
                    "environment": environment,
                    "domain": domain,
                    "window_days": window_days,
                    "status": status,
                    "finding_class": finding_class,
                    "kev": kev,
                    "framework": framework,
                    "control": control,
                    "owner": owner,
                    "sla": sla,
                }
            ),
        )

    def ingest_finding_triage_vex(self, vex: Mapping[str, JsonValue]) -> JsonObject:
        """Ingest an OpenVEX document, applying not_affected/fixed statements as triage."""

        return self._request("POST", "/v1/findings/triage/vex/ingest", json={"vex": dict(vex)})

    def ingest_findings(
        self,
        findings: Sequence[Mapping[str, JsonValue]],
        *,
        source: str | None = None,
        schema_version: str | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
        observed_at: str | None = None,
        reconcile_absent: bool = False,
        idempotency_key: str | None = None,
    ) -> JsonObject:
        """Post normalized findings directly into the control plane."""

        extra_headers: dict[str, str] = {}
        if idempotency_key:
            extra_headers["Idempotency-Key"] = idempotency_key

        return self._request(
            "POST",
            "/v1/findings/bulk",
            json=_strip_none(
                {
                    "findings": [dict(finding) for finding in findings],
                    "source": source,
                    "schema_version": schema_version,
                    "metadata": dict(metadata) if metadata is not None else None,
                    "tenant_id": tenant_id or self.tenant_id,
                    "observed_at": observed_at,
                    "reconcile_absent": reconcile_absent or None,
                }
            ),
            extra_headers=extra_headers or None,
        )

    def register_dataset_version(
        self,
        dataset_id: str,
        *,
        version_id: str | None = None,
        artifact_uri: str | None = None,
        digest: str | None = None,
        digest_algorithm: str | None = None,
        source: str | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Register a dataset version artifact."""

        return self._request(
            "POST",
            f"/v1/datasets/{_quote_path(dataset_id)}/versions",
            json=_strip_none(
                {
                    "version_id": version_id,
                    "artifact_uri": artifact_uri,
                    "digest": digest,
                    "digest_algorithm": digest_algorithm,
                    "source": source,
                    "metadata": dict(metadata) if metadata is not None else None,
                    "tenant_id": tenant_id or self.tenant_id,
                }
            ),
        )

    def dataset_versions(self, dataset_id: str) -> JsonObject:
        """List versions for a dataset."""

        return self._request("GET", f"/v1/datasets/{_quote_path(dataset_id)}/versions")

    def dataset_version(self, dataset_id: str, version_id: str) -> JsonObject:
        """Return one dataset version record."""

        return self._request("GET", f"/v1/datasets/{_quote_path(dataset_id)}/versions/{_quote_path(version_id)}")

    def register_evaluation_run(
        self,
        *,
        evaluation_id: str | None = None,
        name: str | None = None,
        status: str | None = None,
        dataset_id: str | None = None,
        dataset_version_id: str | None = None,
        trace_id: str | None = None,
        model: str | None = None,
        prompt_hash: str | None = None,
        source: str | None = None,
        scores: Mapping[str, float] | None = None,
        summary: Mapping[str, JsonValue] | None = None,
        cases: Sequence[Mapping[str, JsonValue]] | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Register an evaluation run linked to datasets, traces, models, and prompt hashes."""

        return self._request(
            "POST",
            "/v1/evaluations",
            json=_strip_none(
                {
                    "evaluation_id": evaluation_id,
                    "name": name,
                    "status": status,
                    "dataset_id": dataset_id,
                    "dataset_version_id": dataset_version_id,
                    "trace_id": trace_id,
                    "model": model,
                    "prompt_hash": prompt_hash,
                    "source": source,
                    "scores": dict(scores) if scores is not None else None,
                    "summary": dict(summary) if summary is not None else None,
                    "cases": [dict(case) for case in cases] if cases is not None else None,
                    "metadata": dict(metadata) if metadata is not None else None,
                    "tenant_id": tenant_id or self.tenant_id,
                }
            ),
        )

    def evaluation_runs(
        self,
        *,
        dataset_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
    ) -> JsonObject:
        """List evaluation runs for the request tenant."""

        return self._request(
            "GET",
            "/v1/evaluations",
            params=_strip_query_none({"dataset_id": dataset_id, "limit": limit, "offset": offset}),
        )

    def evaluation_run(self, evaluation_id: str) -> JsonObject:
        """Return one evaluation run record."""

        return self._request("GET", f"/v1/evaluations/{_quote_path(evaluation_id)}")

    def agent_manifest(self, *, tenant_id: str | None = None) -> JsonObject:
        """Return the tenant-scoped Agent BOM manifest."""

        return self._request(
            "GET",
            "/v1/agent-bom/manifest",
            params=_strip_query_none({"tenant_id": tenant_id or self.tenant_id}),
        )

    def runtime_production_index(self, *, tenant_id: str | None = None) -> JsonObject:
        """Return the runtime production-index posture summary."""

        return self._request(
            "GET",
            "/v1/runtime/production-index",
            params=_strip_query_none({"tenant_id": tenant_id or self.tenant_id}),
        )

    def ingest_runtime_events(
        self,
        events: Mapping[str, JsonValue] | Sequence[Mapping[str, JsonValue]],
        *,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Persist metadata-only runtime observations for event and session analysis."""

        if isinstance(events, Mapping):
            payload: Mapping[str, JsonValue] = dict(events)
        else:
            payload = {"events": [dict(event) for event in events]}
        return self._request(
            "POST",
            "/v1/runtime/events",
            json=_strip_none(
                {
                    **payload,
                    "tenant_id": tenant_id or self.tenant_id,
                }
            ),
        )

    def runtime_sessions(
        self,
        *,
        limit: int | None = None,
        offset: int | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """List tenant-scoped runtime sessions with event, verdict, and tool summaries."""

        return self._request(
            "GET",
            "/v1/runtime/sessions",
            params=_strip_query_none({"tenant_id": tenant_id or self.tenant_id, "limit": limit, "offset": offset}),
        )

    def runtime_observations(
        self,
        *,
        session_id: str | None = None,
        limit: int | None = None,
        offset: int | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """List tenant-scoped metadata-only runtime observations."""

        return self._request(
            "GET",
            "/v1/runtime/observations",
            params=_strip_query_none(
                {
                    "tenant_id": tenant_id or self.tenant_id,
                    "session_id": session_id,
                    "limit": limit,
                    "offset": offset,
                }
            ),
        )

    def runtime_session_observations(
        self,
        session_id: str,
        *,
        limit: int | None = None,
        offset: int | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """List observations for one runtime session."""

        return self._request(
            "GET",
            f"/v1/runtime/sessions/{_quote_path(session_id)}/observations",
            params=_strip_query_none({"tenant_id": tenant_id or self.tenant_id, "limit": limit, "offset": offset}),
        )

    def intel_lookup(self, advisory_id: str) -> JsonObject:
        """Look up one advisory by CVE, GHSA, or OSV identifier."""

        return self._request("GET", f"/v1/intel/advisories/{_quote_path(advisory_id)}")

    def intel_match(
        self,
        *,
        packages: Sequence[Mapping[str, JsonValue]] | None = None,
        purl: str | None = None,
        ecosystem: str | None = None,
        name: str | None = None,
        version: str | None = None,
        limit: int | None = None,
    ) -> JsonObject:
        """Match package coordinates against advisory intelligence."""

        return self._request(
            "POST",
            "/v1/intel/match",
            json=_strip_none(
                {
                    "packages": [dict(package) for package in packages] if packages is not None else None,
                    "purl": purl,
                    "ecosystem": ecosystem,
                    "name": name,
                    "version": version,
                    "limit": limit,
                }
            ),
        )

    def intel_sources(self) -> JsonObject:
        """List configured advisory intelligence sources and freshness."""

        return self._request("GET", "/v1/intel/sources")

    def create_cloud_connection(
        self,
        *,
        provider: str,
        display_name: str,
        role_ref: str,
        external_id: str,
        regions: Sequence[str] | None = None,
        auth_params: Mapping[str, str] | None = None,
        scan_interval_minutes: int | None = None,
        inventory_scope: str | None = None,
        scan_mode: str | None = None,
        auto_scan_on_create: bool | None = None,
    ) -> JsonObject:
        """Register a read-only cloud connection with the control plane.

        Builds the body via the shared request-builder so the fields match the
        API's ``CloudConnectionCreate`` schema exactly. ``external_id`` is the
        single write-only secret — it is sent so the server can encrypt it at
        rest and is never returned in the response (and must never be logged).
        """
        from agent_bom.cloud.connection_request import build_connection_create_body

        body = build_connection_create_body(
            provider=provider,
            display_name=display_name,
            role_ref=role_ref,
            external_id=external_id,
            regions=regions,
            auth_params=auth_params,
            scan_interval_minutes=scan_interval_minutes,
            inventory_scope=inventory_scope,
            scan_mode=scan_mode,
            auto_scan_on_create=auto_scan_on_create,
        )
        return self._request("POST", "/v1/cloud/connections", json=body)

    def test_cloud_connection(self, connection_id: str) -> JsonObject:
        """Validate a connection's brokered read-only credential (no scan)."""

        return self._request("POST", f"/v1/cloud/connections/{_quote_path(connection_id)}/test")

    def scan_cloud_connection(self, connection_id: str) -> JsonObject:
        """Launch a read-only scan for a stored connection via the broker."""

        return self._request("POST", f"/v1/cloud/connections/{_quote_path(connection_id)}/scan")

    # ── Governance blueprints (persisted AI-system blueprints + approval) ──────

    def list_blueprints(self, *, limit: int | None = None, offset: int | None = None) -> JsonObject:
        """List persisted AI-system blueprints for the active tenant (paginated)."""

        params = _strip_query_none({"limit": limit, "offset": offset})
        return self._request("GET", "/v1/governance/blueprints", params=params)

    def get_blueprint(self, blueprint_id: str) -> JsonObject:
        """Fetch one blueprint plus its version history and approval state."""

        return self._request("GET", f"/v1/governance/blueprints/{_quote_path(blueprint_id)}")

    def create_blueprint(
        self,
        *,
        name: str,
        owner: str,
        owner_type: str | None = None,
        description: str | None = None,
        composition: Mapping[str, JsonValue] | None = None,
    ) -> JsonObject:
        """Create a blueprint with an initial draft version 1."""

        body = _strip_none(
            {
                "name": name,
                "owner": owner,
                "owner_type": owner_type,
                "description": description,
                "composition": dict(composition) if composition is not None else None,
            }
        )
        return self._request("POST", "/v1/governance/blueprints", json=body)

    def seed_blueprints(self) -> JsonObject:
        """Seed the tenant's blueprints from the canonical role archetypes (idempotent)."""

        return self._request("POST", "/v1/governance/blueprints/seed")

    def submit_blueprint_version(self, blueprint_id: str, version: int) -> JsonObject:
        """Submit a draft blueprint version for approval (draft → pending)."""

        return self._request("POST", f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/submit")

    def approve_blueprint_version(self, blueprint_id: str, version: int, *, note: str | None = None) -> JsonObject:
        """Approve a pending blueprint version (requires the admin/governance role)."""

        return self._request(
            "POST",
            f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/approve",
            json=_strip_none({"note": note}),
        )

    def reject_blueprint_version(self, blueprint_id: str, version: int, *, note: str | None = None) -> JsonObject:
        """Reject a pending blueprint version (requires the admin/governance role)."""

        return self._request(
            "POST",
            f"/v1/governance/blueprints/{_quote_path(blueprint_id)}/versions/{int(version)}/reject",
            json=_strip_none({"note": note}),
        )

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json: Mapping[str, JsonValue] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        headers = self._headers(json is not None)
        if extra_headers:
            headers.update(extra_headers)
        response = self._client.request(method, self._url(path), params=params, json=json, headers=headers)
        text = response.text
        if response.status_code < 200 or response.status_code >= 300:
            raise AgentBomApiError(
                f"agent-bom request failed: {response.status_code}",
                status_code=response.status_code,
                body=text,
            )
        if not text:
            return {}
        data = response.json()
        if not isinstance(data, dict):
            raise AgentBomApiError("agent-bom response was not a JSON object", status_code=response.status_code, body=text)
        return data

    def _request_list(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json: Mapping[str, JsonValue] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> list[JsonObject]:
        """Like :meth:`_request` but for endpoints returning a JSON array."""
        headers = self._headers(json is not None)
        if extra_headers:
            headers.update(extra_headers)
        response = self._client.request(method, self._url(path), params=params, json=json, headers=headers)
        text = response.text
        if response.status_code < 200 or response.status_code >= 300:
            raise AgentBomApiError(
                f"agent-bom request failed: {response.status_code}",
                status_code=response.status_code,
                body=text,
            )
        if not text:
            return []
        data = response.json()
        if not isinstance(data, list):
            raise AgentBomApiError("agent-bom response was not a JSON array", status_code=response.status_code, body=text)
        return [item for item in data if isinstance(item, dict)]

    def _url(self, path: str) -> str:
        if path.startswith(("http://", "https://")):
            return path
        return f"{self.base_url}/{path.lstrip('/')}"

    def _headers(self, has_body: bool) -> dict[str, str]:
        headers = {"accept": "application/json", **self.default_headers}
        if has_body:
            headers["content-type"] = "application/json"
        if self.api_key:
            headers["x-api-key"] = self.api_key
        if self.bearer_token:
            headers["authorization"] = f"Bearer {self.bearer_token}"
        if self.tenant_id:
            headers["x-agent-bom-tenant-id"] = self.tenant_id
        return headers


def _quote_path(value: str) -> str:
    return quote(value, safe="")


def _strip_none(values: Mapping[str, Any]) -> JsonObject:
    return {key: value for key, value in values.items() if value is not None}


def _strip_query_none(values: Mapping[str, QueryValue]) -> dict[str, str | int | float | bool]:
    return {key: value for key, value in values.items() if value is not None}
