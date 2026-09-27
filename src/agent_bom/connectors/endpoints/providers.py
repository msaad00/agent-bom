"""Vendor paging and explicitly scoped normalization; no hostname joins."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from agent_bom.device_posture import CrowdStrikeConnector, DeviceSignal

from .models import Connection, scoped_device_id
from .transport import CollectionError, EndpointClient


@dataclass
class Page:
    devices: list[DeviceSignal]
    cursor: str
    expected: int
    complete: bool


def _object(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CollectionError("invalid_provider_response")
    return value


def _rows(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or any(not isinstance(row, dict) for row in value):
        raise CollectionError("invalid_provider_response")
    return value


def _total(value: Any) -> int:
    if type(value) is not int or value < 0:
        raise CollectionError("missing_inventory_denominator")
    return value


def _id(value: Any) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > 200:
        raise CollectionError("missing_or_invalid_device_id")
    return value.strip()


def _jamf_signal(row: dict[str, Any], connection: Connection) -> DeviceSignal:
    general = _object(row.get("general") or {})
    os_info = _object(row.get("operatingSystem") or {})
    remote = _object(general.get("remoteManagement") or {})
    encrypted = os_info.get("fileVault2Status")
    if encrypted is not None and not isinstance(encrypted, str):
        raise CollectionError("invalid_encryption_posture")
    signal = DeviceSignal(
        tenant_id=connection.tenant_id,
        device_id=_id(row.get("id")),
        source="jamf",
        managed=remote.get("managed") if isinstance(remote.get("managed"), bool) else None,
        disk_encrypted=True
        if encrypted == "ALL_ENCRYPTED"
        else False
        if encrypted in {"NOT_ENCRYPTED", "BOOT_ENCRYPTED", "SOME_ENCRYPTED"}
        else None,
        hostname=str(general.get("name") or "")[:250],
        os_version=str(os_info.get("version") or "")[:120],
        # reportDate timestamps the inventory evidence, not just an MDM check-in.
        last_seen=str(general.get("reportDate") or ""),
        attributes={"udid": str(row.get("udid") or "")[:200], "management_id": str(general.get("managementId") or "")[:200]},
    )
    return signal


def scope_signal(signal: DeviceSignal, connection: Connection, observed_at: str) -> DeviceSignal:
    vendor_id = signal.device_id
    signal.device_id = scoped_device_id(connection.tenant_id, connection.provider, connection.account_id, vendor_id)
    signal.observed_at = observed_at
    signal.attributes.update(
        {
            "vendor_device_id": vendor_id,
            "account_id": connection.account_id,
            "connection_id": connection.id,
            "evidence_kind": "provider_inventory",
            "collected_at": observed_at,
            "freshness_hours": connection.freshness_hours,
        }
    )
    signal.attributes["freshness"] = freshness(signal.last_seen, connection.freshness_hours, observed_at)
    # Stale/absent evidence cannot satisfy an access-policy predicate.
    if signal.attributes["freshness"] != "fresh":
        signal.managed = signal.compliant = signal.disk_encrypted = None
    return signal


def freshness(last_seen: str, hours: int, at: str) -> str:
    try:
        seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
        current = datetime.fromisoformat(at.replace("Z", "+00:00"))
        if seen.tzinfo is None or current.tzinfo is None:
            return "unknown"
        age = (current.astimezone(timezone.utc) - seen.astimezone(timezone.utc)).total_seconds()
        return "fresh" if 0 <= age <= hours * 3600 else "stale" if age > 0 else "unknown"
    except (ValueError, TypeError):
        return "unknown"


def jamf_page(client: EndpointClient, connection: Connection, cursor: str, at: str) -> Page:
    page = int(cursor or "0")
    result = client.get(
        "/api/v4/computers-inventory",
        [
            ("page", str(page)),
            ("page-size", str(connection.page_size)),
            ("sort", "id:asc"),
            ("section", "GENERAL"),
            ("section", "OPERATING_SYSTEM"),
        ],
    )
    rows, total = _rows(result.get("results")), _total(result.get("totalCount"))
    if len(rows) > connection.page_size or (not rows and page * connection.page_size < total):
        raise CollectionError("inventory_page_gap")
    signals = [scope_signal(_jamf_signal(row, connection), connection, at) for row in rows]
    return Page(signals, str(page + 1), total, (page * connection.page_size + len(rows)) >= total)


def falcon_page(client: EndpointClient, connection: Connection, cursor: str, at: str) -> Page:
    params = [("limit", str(connection.page_size))]
    if cursor:
        params.append(("offset", cursor))
    result = client.get("/devices/queries/devices-scroll/v1", params)
    ids = result.get("resources")
    if not isinstance(ids, list) or len(ids) > connection.page_size:
        raise CollectionError("invalid_provider_response")
    ids = [_id(value) for value in ids]
    pagination = _object(_object(result.get("meta")).get("pagination"))
    total = _total(pagination.get("total"))
    next_cursor = str(pagination.get("offset") or "")
    if ids and (not next_cursor or next_cursor == cursor):
        raise CollectionError("inventory_cursor_stalled")
    if not ids:
        return Page([], "", total, True)
    details = client.get("/devices/entities/devices/v2", [("ids", value) for value in ids])
    rows = _rows(details.get("resources"))
    if {_id(row.get("device_id")) for row in rows} != set(ids) or len(rows) != len(ids):
        raise CollectionError("host_details_gap")
    if any(str(row.get("cid") or "").lower() != connection.account_id for row in rows):
        raise CollectionError("provider_account_mismatch")
    signals = CrowdStrikeConnector().normalize({"resources": rows}, tenant_id=connection.tenant_id)
    return Page([scope_signal(signal, connection, at) for signal in signals], next_cursor, total, False)
