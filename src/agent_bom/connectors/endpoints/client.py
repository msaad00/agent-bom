"""Python client surface for endpoint inventory and explicit agent associations."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from agent_bom.client_types import JsonObject, JsonValue, QueryValue


class EndpointClientMixin:
    """Uses the parent client's authentication, transport and error handling."""

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

    def bind_endpoint_agent(self, device_id: str, agent_id: str, *, active: bool = True) -> JsonObject:
        return self._request(
            "PUT",
            f"/v1/endpoint-connectors/devices/{quote(device_id, safe='')}/agent-binding",
            json={"agent_id": agent_id, "active": active},
        )

    def endpoint_connections(self) -> JsonObject:
        return self._request("GET", "/v1/endpoint-connectors")

    def create_endpoint_connection(self, body: JsonObject) -> JsonObject:
        return self._request("POST", "/v1/endpoint-connectors", json=body)

    def sync_endpoint_connection(self, connection_id: str, *, restart: bool = False, max_pages: int = 5) -> JsonObject:
        return self._request(
            "POST", f"/v1/endpoint-connectors/{quote(connection_id, safe='')}/sync", json={"restart": restart, "max_pages": max_pages}
        )

    def endpoint_devices(self, connection_id: str, *, limit: int = 100, offset: int = 0) -> JsonObject:
        return self._request(
            "GET", f"/v1/endpoint-connectors/{quote(connection_id, safe='')}/devices", params={"limit": limit, "offset": offset}
        )

    def update_endpoint_connection(self, connection_id: str, body: JsonObject) -> JsonObject:
        return self._request("PATCH", f"/v1/endpoint-connectors/{quote(connection_id, safe='')}", json=body)
