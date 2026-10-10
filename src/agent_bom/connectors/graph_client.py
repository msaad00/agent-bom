"""Graph investigation transport methods for the control-plane client."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from urllib.parse import quote

from agent_bom.core.json_types import JsonObject, JsonValue, QueryValue


class GraphClientMixin:
    """Reuse the parent client authentication, request transport and errors."""

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Mapping[str, QueryValue] | None = None,
        json: Mapping[str, JsonValue] | None = None,
        extra_headers: Mapping[str, str] | None = None,
    ) -> JsonObject:
        raise NotImplementedError

    def compromise_assessment(
        self,
        *,
        root_node_id: str,
        scan_id: str,
        assume_control: bool,
        snapshot_generation: str | None = None,
        affected_node_id: str | None = None,
        assume_exploitation: bool = False,
        max_relationships: int = 128,
        max_evidence_age_seconds: int = 3600,
    ) -> JsonObject:
        """Assess an explicit assumption against a tenant-authorized graph revision."""
        return self._request(
            "POST",
            "/v1/graph/compromise",
            json={
                "root_node_id": root_node_id,
                "scan_id": scan_id,
                "assume_control": assume_control,
                "snapshot_generation": snapshot_generation,
                "affected_node_id": affected_node_id,
                "assume_exploitation": assume_exploitation,
                "max_relationships": max_relationships,
                "max_evidence_age_seconds": max_evidence_age_seconds,
            },
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

        return self._request("GET", f"/v1/graph/correlations/{quote(correlation_id, safe='')}")

    def list_graph_correlations(self, *, limit: int = 50) -> JsonObject:
        """List recent tenant-scoped graph correlation runs."""

        return self._request("GET", "/v1/graph/correlations", params={"limit": limit})
