"""EDR/MDM device-posture ingest → ABAC device-attribute enrichment.

Endpoint Detection & Response (EDR) and Mobile Device Management (MDM) systems
own the ground truth for whether a device is *managed*, *compliant*, and
*disk-encrypted*. Conditional-access (ABAC) policies
(:class:`agent_bom.api.agent_identity_store.ConditionalAccessPolicy`, device
attributes added for #3906) can *require* those postures — but only if the
signals reach the decision point. This module is that bridge:

    vendor payload  ──normalize──▶  DeviceSignal  ──put──▶  DevicePostureStore
                                                                    │
                       AccessContext ◀──apply_device_posture────────┘

**Vendor-neutral by design.** The canonical unit is :class:`DeviceSignal`.
Concrete adapters normalize a specific source's payload shape into that unit;
they are pure field-mappers over an *already-fetched* JSON payload (read-only,
agentless — no live vendor API client and no stored vendor credentials ship
here). Two adapters are provided as concrete shapes — one EDR (CrowdStrike host
API) and one MDM (Microsoft Intune ``managedDevices``) — alongside a ``generic``
adapter that accepts the canonical shape directly, which is the documented
generic **POST** ingest contract. This is deliberately honest: agent-bom ships a
generic device-posture ingest plus two documented vendor field-mappings, not a
fleet of live vendor integrations.

The signals carry no secret material — device id, posture booleans, OS version,
and last-seen only.
"""

from __future__ import annotations

import builtins
import json
import sqlite3
import threading
from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.api.agent_identity_store import AccessContext


@dataclass
class DeviceSignal:
    """A vendor-neutral device posture/compliance signal (no secrets).

    ``managed`` / ``compliant`` / ``disk_encrypted`` are tri-state: ``True`` /
    ``False`` / ``None`` (unknown / not reported). ABAC ``require_device_*``
    conditions treat only ``True`` as satisfying — unknown fails closed.
    """

    tenant_id: str
    device_id: str
    source: str  # crowdstrike | intune | jamf | generic | ...
    managed: bool | None = None
    compliant: bool | None = None
    disk_encrypted: bool | None = None
    os_version: str = ""
    hostname: str = ""
    risk_level: str = ""  # low | medium | high | critical | ""
    last_seen: str = ""  # ISO-8601 when the source last observed the device
    observed_at: str = ""  # ISO-8601 when agent-bom ingested this signal
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_public_dict(self) -> dict[str, Any]:
        return asdict(self)


# ── Store ────────────────────────────────────────────────────────────────────


class DevicePostureStore(Protocol):
    def put(self, signal: DeviceSignal) -> None: ...

    def get(self, device_id: str, *, tenant_id: str) -> DeviceSignal | None: ...

    def list(self, tenant_id: str, *, limit: int = 500) -> builtins.list[DeviceSignal]: ...


class InMemoryDevicePostureStore:
    """Process-local per-tenant device-posture cache. Ephemeral (lost on restart)."""

    def __init__(self) -> None:
        # Keyed by the composite (tenant_id, device_id) so a device id can never
        # cross tenants — enrichment for tenant A never leaks to tenant B.
        self._by_key: dict[tuple[str, str], DeviceSignal] = {}
        self._lock = threading.Lock()

    def put(self, signal: DeviceSignal) -> None:
        with self._lock:
            self._by_key[(signal.tenant_id, signal.device_id)] = signal

    def get(self, device_id: str, *, tenant_id: str) -> DeviceSignal | None:
        with self._lock:
            return self._by_key.get((tenant_id, device_id))

    def list(self, tenant_id: str, *, limit: int = 500) -> builtins.list[DeviceSignal]:
        with self._lock:
            rows = [s for (t, _d), s in self._by_key.items() if t == tenant_id]
        return rows[:limit]


class SQLiteDevicePostureStore:
    """Single-node durable device-posture cache backed by SQLite."""

    def __init__(self, db_path: str = "agent_bom.db") -> None:
        self._db_path = db_path
        self._local = threading.local()
        self._lock = threading.Lock()
        self._init_db()

    @property
    def _conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._local.conn = sqlite3.connect(self._db_path, check_same_thread=False)
            self._local.conn.execute("PRAGMA journal_mode=WAL")
        conn: sqlite3.Connection = self._local.conn
        return conn

    def _init_db(self) -> None:
        from agent_bom.api.storage_schema import ensure_sqlite_schema_version

        ensure_sqlite_schema_version(self._conn, "device_posture")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_posture (
                tenant_id TEXT NOT NULL,
                device_id TEXT NOT NULL,
                source TEXT NOT NULL,
                observed_at TEXT NOT NULL,
                data TEXT NOT NULL,
                PRIMARY KEY (tenant_id, device_id)
            )
            """
        )
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_device_posture_tenant ON device_posture(tenant_id)")
        self._conn.commit()

    def put(self, signal: DeviceSignal) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO device_posture (tenant_id, device_id, source, observed_at, data)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, device_id)
                DO UPDATE SET source=excluded.source, observed_at=excluded.observed_at, data=excluded.data
                """,
                (signal.tenant_id, signal.device_id, signal.source, signal.observed_at, json.dumps(asdict(signal), sort_keys=True)),
            )
            self._conn.commit()

    def get(self, device_id: str, *, tenant_id: str) -> DeviceSignal | None:
        row = self._conn.execute(
            "SELECT data FROM device_posture WHERE tenant_id = ? AND device_id = ?",
            (tenant_id, device_id),
        ).fetchone()
        return DeviceSignal(**json.loads(row[0])) if row else None

    def list(self, tenant_id: str, *, limit: int = 500) -> builtins.list[DeviceSignal]:
        rows = self._conn.execute(
            "SELECT data FROM device_posture WHERE tenant_id = ? ORDER BY observed_at DESC LIMIT ?",
            (tenant_id, limit),
        ).fetchall()
        return [DeviceSignal(**json.loads(r[0])) for r in rows]


# ── Connectors (vendor-neutral normalizers) ──────────────────────────────────


def _as_bool(value: Any) -> bool | None:
    """Coerce a vendor field to a tri-state bool. Unknown → ``None``."""
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "compliant", "managed", "encrypted", "enabled", "on"}:
        return True
    if text in {"false", "no", "0", "noncompliant", "unmanaged", "notencrypted", "disabled", "off"}:
        return False
    return None


class DevicePostureConnector(Protocol):
    source: str

    def normalize(self, payload: dict[str, Any], *, tenant_id: str) -> builtins.list[DeviceSignal]: ...


class GenericDevicePostureConnector:
    """Accept the canonical device-posture shape directly (the POST ingest).

    Expected payload::

        {"signals": [{"device_id": "...", "managed": true, "compliant": true,
                      "disk_encrypted": true, "os_version": "...",
                      "hostname": "...", "risk_level": "low",
                      "last_seen": "...", "attributes": {...}}]}
    """

    source = "generic"

    def normalize(self, payload: dict[str, Any], *, tenant_id: str) -> builtins.list[DeviceSignal]:
        out: builtins.list[DeviceSignal] = []
        for row in payload.get("signals", []) or []:
            device_id = str(row.get("device_id") or "").strip()
            if not device_id:
                continue
            out.append(
                DeviceSignal(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    source=str(row.get("source") or self.source),
                    managed=_as_bool(row.get("managed")),
                    compliant=_as_bool(row.get("compliant")),
                    disk_encrypted=_as_bool(row.get("disk_encrypted")),
                    os_version=str(row.get("os_version") or ""),
                    hostname=str(row.get("hostname") or ""),
                    risk_level=str(row.get("risk_level") or ""),
                    last_seen=str(row.get("last_seen") or ""),
                    attributes=dict(row.get("attributes") or {}),
                )
            )
        return out


class CrowdStrikeConnector:
    """Normalize a CrowdStrike Falcon host-details payload (EDR).

    Field mapping (``/devices/entities/devices/v2`` ``resources[]``):
    a reporting sensor ⇒ ``managed``; ``status == "normal"`` and *not* in
    ``reduced_functionality_mode`` ⇒ ``compliant``.
    """

    source = "crowdstrike"

    def normalize(self, payload: dict[str, Any], *, tenant_id: str) -> builtins.list[DeviceSignal]:
        out: builtins.list[DeviceSignal] = []
        for host in payload.get("resources", []) or []:
            device_id = str(host.get("device_id") or host.get("id") or "").strip()
            if not device_id:
                continue
            status = str(host.get("status") or "").strip().lower()
            rfm = _as_bool(host.get("reduced_functionality_mode"))
            last_seen = str(host.get("last_seen") or "")
            agent_version = str(host.get("agent_version") or "")
            # Tri-state compliance — a missing/empty status is UNKNOWN, not
            # compliant. Only assert compliant on an explicit "normal" that is
            # not in reduced-functionality mode; RFM is a known-bad signal.
            compliant: bool | None
            if rfm is True:
                compliant = False
            elif status:
                compliant = status == "normal"
            else:
                compliant = None
            # Only assert managed when the payload actually evidences a reporting
            # / enrolled sensor (status, a last-seen, or an agent version). A
            # sparse device_id-only entry leaves managed unknown so a
            # require_device_managed gate fails closed.
            managed: bool | None = True if (status or last_seen or agent_version) else None
            out.append(
                DeviceSignal(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    source=self.source,
                    managed=managed,
                    compliant=compliant,
                    disk_encrypted=_as_bool(host.get("disk_encryption_status")),
                    os_version=str(host.get("os_version") or ""),
                    hostname=str(host.get("hostname") or ""),
                    risk_level=str(host.get("risk_level") or ""),
                    last_seen=last_seen,
                    attributes={"platform": str(host.get("platform_name") or "")},
                )
            )
        return out


class IntuneConnector:
    """Normalize a Microsoft Intune ``managedDevices`` payload (MDM).

    Field mapping (Graph ``deviceManagement/managedDevices`` ``value[]``):
    ``complianceState == "compliant"`` ⇒ ``compliant``;
    ``managementState``/``managementAgent`` present ⇒ ``managed``;
    ``isEncrypted`` ⇒ ``disk_encrypted``.
    """

    source = "intune"

    def normalize(self, payload: dict[str, Any], *, tenant_id: str) -> builtins.list[DeviceSignal]:
        out: builtins.list[DeviceSignal] = []
        for dev in payload.get("value", []) or []:
            device_id = str(dev.get("id") or "").strip()
            if not device_id:
                continue
            compliance = str(dev.get("complianceState") or "").strip().lower()
            mgmt_state = str(dev.get("managementState") or dev.get("managementAgent") or "").strip().lower()
            out.append(
                DeviceSignal(
                    tenant_id=tenant_id,
                    device_id=device_id,
                    source=self.source,
                    managed=bool(mgmt_state) and mgmt_state not in {"none", "unmanaged", "discovered"},
                    compliant=(compliance == "compliant") if compliance else None,
                    disk_encrypted=_as_bool(dev.get("isEncrypted")),
                    os_version=str(dev.get("osVersion") or ""),
                    hostname=str(dev.get("deviceName") or ""),
                    last_seen=str(dev.get("lastSyncDateTime") or ""),
                    attributes={"os": str(dev.get("operatingSystem") or "")},
                )
            )
        return out


_CONNECTORS: dict[str, type] = {
    "generic": GenericDevicePostureConnector,
    "crowdstrike": CrowdStrikeConnector,
    "intune": IntuneConnector,
}


def create_device_connector(name: str) -> DevicePostureConnector:
    """Create a device-posture connector by source name."""
    cls = _CONNECTORS.get(name.strip().lower())
    if cls is None:
        raise ValueError(f"Unknown device-posture connector: {name!r}. Available: {list_device_connectors()}")
    return cls()  # type: ignore[return-value]


def list_device_connectors() -> builtins.list[str]:
    return sorted(_CONNECTORS.keys())


# ── ABAC enrichment ──────────────────────────────────────────────────────────


def apply_device_posture(store: DevicePostureStore, ctx: "AccessContext", *, tenant_id: str) -> "AccessContext":
    """Fill ``ctx`` device-posture attributes from the store for its device id.

    A no-op when the request supplied no ``device_id`` or the device is unknown
    to this tenant — leaving the posture attributes ``None`` so a
    ``require_device_*`` policy fails closed on an unmanaged / unknown device.
    Mutates and returns ``ctx``.
    """
    if not ctx.device_id:
        return ctx
    signal = store.get(ctx.device_id, tenant_id=tenant_id)
    if signal is None:
        return ctx
    ctx.device_managed = signal.managed
    ctx.device_compliant = signal.compliant
    ctx.device_disk_encrypted = signal.disk_encrypted
    return ctx


# ── Store singleton ──────────────────────────────────────────────────────────

_DEVICE_POSTURE_STORE: DevicePostureStore | None = None
_STORE_LOCK = threading.Lock()


def get_device_posture_store() -> DevicePostureStore:
    """Return the process device-posture store, durable by default.

    Node-local durable SQLite by default; in-memory only on the explicit
    ephemeral opt-out (``AGENT_BOM_EPHEMERAL_STORE``). A shared Postgres tier for
    multi-replica posture is a tracked follow-up; on a Postgres deployment this
    falls back to node-local SQLite (each replica caches independently), which is
    safe because posture is an enrichment cache re-populated on ingest.
    """
    global _DEVICE_POSTURE_STORE
    if _DEVICE_POSTURE_STORE is not None:
        return _DEVICE_POSTURE_STORE
    with _STORE_LOCK:
        if _DEVICE_POSTURE_STORE is None:
            from agent_bom.api.durable_store import select_backend, sqlite_path

            backend = select_backend()
            if backend == "memory":
                _DEVICE_POSTURE_STORE = InMemoryDevicePostureStore()
            else:
                _DEVICE_POSTURE_STORE = SQLiteDevicePostureStore(sqlite_path())
    return _DEVICE_POSTURE_STORE


def set_device_posture_store(store: DevicePostureStore | None) -> None:
    global _DEVICE_POSTURE_STORE
    with _STORE_LOCK:
        _DEVICE_POSTURE_STORE = store


def ingest_device_signals(
    store: DevicePostureStore, source: str, payload: dict[str, Any], *, tenant_id: str
) -> builtins.list[DeviceSignal]:
    """Normalize a vendor/generic payload and persist every signal. Returns them."""
    connector = create_device_connector(source)
    signals = connector.normalize(payload, tenant_id=tenant_id)
    for signal in signals:
        store.put(signal)
    return signals


__all__ = [
    "CrowdStrikeConnector",
    "DevicePostureConnector",
    "DevicePostureStore",
    "DeviceSignal",
    "GenericDevicePostureConnector",
    "InMemoryDevicePostureStore",
    "IntuneConnector",
    "SQLiteDevicePostureStore",
    "apply_device_posture",
    "create_device_connector",
    "get_device_posture_store",
    "ingest_device_signals",
    "list_device_connectors",
    "set_device_posture_store",
]
