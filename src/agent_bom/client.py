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

    def exposure_paths(self, *, limit: int | None = None, min_risk: int | None = None, tenant_id: str | None = None) -> JsonObject:
        """List graph exposure paths for the request tenant."""

        return self._request(
            "GET",
            "/v1/graph/exposure-paths",
            params=_strip_query_none(
                {
                    "tenant_id": tenant_id or self.tenant_id,
                    "limit": limit,
                    "min_risk": min_risk,
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
    ) -> JsonObject:
        """List normalized findings from scan jobs and bulk ingests."""

        return self._request(
            "GET",
            "/v1/findings",
            params=_strip_query_none(
                {
                    "severity": severity,
                    "sort": sort,
                    "limit": limit,
                    "offset": offset,
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

    def export_finding_triage_vex(self) -> JsonObject:
        """Export OpenVEX for eligible finding triage decisions."""

        return self._request("GET", "/v1/findings/triage/vex")

    def ingest_findings(
        self,
        findings: Sequence[Mapping[str, JsonValue]],
        *,
        source: str | None = None,
        schema_version: str | None = None,
        metadata: Mapping[str, JsonValue] | None = None,
        tenant_id: str | None = None,
    ) -> JsonObject:
        """Post normalized findings directly into the control plane."""

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
                }
            ),
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

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json: Mapping[str, JsonValue] | None = None,
    ) -> JsonObject:
        response = self._client.request(method, self._url(path), params=params, json=json, headers=self._headers(json is not None))
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
