"""Finding delta-stream connector for SIEM and data-lake sinks (#3514).

Emits **new**, **resolved**, and **changed** hub finding events since the last
watermark using the hardened :mod:`agent_bom.delivery` client (retries, DLQ,
circuit breaker, idempotency). Full snapshot re-list is not required on the
read path — deltas are computed from current-state before/after a batch ingest
plus optional reconcile-absent semantics.
"""

from __future__ import annotations

import logging
import sqlite3
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from agent_bom.api.finding_lifecycle import resolve_canonical_id
from agent_bom.delivery import Delivery, DeliveryClient, Destination, get_delivery_client
from agent_bom.security import sanitize_sensitive_payload

logger = logging.getLogger(__name__)

DeltaEventKind = Literal["new", "resolved", "changed"]
DeltaFormat = Literal["ndjson", "ocsf"]


def _symbol_reachability_from_finding(finding: dict[str, Any]) -> tuple[str | None, tuple[str, ...]]:
    """Read symbol reachability from top-level keys or ``evidence`` (export shape)."""
    evidence = finding.get("evidence")
    symbol_reachability = finding.get("symbol_reachability")
    reachable_affected_symbols = finding.get("reachable_affected_symbols")
    if isinstance(evidence, dict):
        if symbol_reachability is None:
            symbol_reachability = evidence.get("symbol_reachability")
        if reachable_affected_symbols is None:
            reachable_affected_symbols = evidence.get("reachable_affected_symbols")
    if symbol_reachability is not None and not isinstance(symbol_reachability, str):
        symbol_reachability = str(symbol_reachability)
    if reachable_affected_symbols is None:
        symbols: tuple[str, ...] = ()
    elif isinstance(reachable_affected_symbols, list):
        symbols = tuple(str(item) for item in reachable_affected_symbols)
    else:
        symbols = ()
    return symbol_reachability, symbols


def _enrich_finding_symbol_reachability(
    finding: dict[str, Any],
    *,
    symbol_reachability: str | None,
    reachable_affected_symbols: tuple[str, ...],
) -> dict[str, Any]:
    """Promote symbol reachability onto the finding dict for delta payloads."""
    enriched = dict(finding)
    if symbol_reachability is not None and "symbol_reachability" not in enriched:
        enriched["symbol_reachability"] = symbol_reachability
    if reachable_affected_symbols and "reachable_affected_symbols" not in enriched:
        enriched["reachable_affected_symbols"] = list(reachable_affected_symbols)
    return enriched


class DeltaStreamError(RuntimeError):
    """Raised for invalid connector configuration."""


@dataclass(frozen=True)
class FindingSnapshot:
    canonical_id: str
    severity: str
    severity_rank: int
    cvss_score: float
    effective_reach_score: float
    symbol_reachability: str | None
    reachable_affected_symbols: tuple[str, ...]
    status: str
    finding: dict[str, Any]

    @classmethod
    def from_finding(cls, finding: dict[str, Any], *, source: str = "") -> FindingSnapshot:
        canonical = str(finding.get("canonical_id") or resolve_canonical_id(finding, source=source))
        symbol_reachability, reachable_affected_symbols = _symbol_reachability_from_finding(finding)
        return cls(
            canonical_id=canonical,
            severity=str(finding.get("severity") or "unknown").lower(),
            severity_rank=int(finding.get("severity_rank") or 0),
            cvss_score=float(finding.get("cvss_score") or 0.0),
            effective_reach_score=float(finding.get("effective_reach_score") or 0.0),
            symbol_reachability=symbol_reachability,
            reachable_affected_symbols=reachable_affected_symbols,
            status=str(finding.get("status") or "open"),
            finding=_enrich_finding_symbol_reachability(
                finding,
                symbol_reachability=symbol_reachability,
                reachable_affected_symbols=reachable_affected_symbols,
            ),
        )

    def material_fields_changed(self, other: FindingSnapshot) -> bool:
        return (
            self.severity != other.severity
            or self.severity_rank != other.severity_rank
            or self.cvss_score != other.cvss_score
            or self.effective_reach_score != other.effective_reach_score
            or self.symbol_reachability != other.symbol_reachability
            or self.reachable_affected_symbols != other.reachable_affected_symbols
            or self.status != other.status
        )


@dataclass(frozen=True)
class FindingDeltaEvent:
    kind: DeltaEventKind
    tenant_id: str
    canonical_id: str
    observed_at: str
    batch_id: str
    source: str
    finding: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "finding_delta.v1",
            "tenant_id": self.tenant_id,
            "event_type": self.kind,
            "canonical_id": self.canonical_id,
            "observed_at": self.observed_at,
            "batch_id": self.batch_id,
            "source": self.source,
            "finding": sanitize_sensitive_payload(self.finding),
        }


@dataclass(frozen=True)
class DeltaStreamDestination:
    destination_id: str
    url: str
    format: DeltaFormat = "ndjson"
    kind: str = "delta_stream"
    auth_scheme: str = ""
    auth_token: str = ""
    signing_secret: str = ""

    def to_delivery_destination(self) -> Destination:
        return Destination(
            destination_id=self.destination_id,
            url=self.url,
            kind=self.kind,
            auth_scheme=self.auth_scheme,
            auth_token=self.auth_token,
            signing_secret=self.signing_secret,
        )


@dataclass(frozen=True)
class DeltaWatermark:
    observed_at: str
    batch_id: str
    updated_at: str


@dataclass
class InMemoryDeltaSink:
    """Test double that captures emitted delta batches without HTTP."""

    batches: list[dict[str, Any]] = field(default_factory=list)

    def record(self, payload: dict[str, Any]) -> None:
        self.batches.append(payload)


class DeltaStreamStore:
    """SQLite watermark ledger per (tenant, destination)."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS delta_stream_watermarks (
                    tenant_id TEXT NOT NULL,
                    destination_id TEXT NOT NULL,
                    observed_at TEXT NOT NULL,
                    batch_id TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (tenant_id, destination_id)
                )
                """
            )

    def get_watermark(self, tenant_id: str, destination_id: str) -> DeltaWatermark | None:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT observed_at, batch_id, updated_at
                FROM delta_stream_watermarks
                WHERE tenant_id = ? AND destination_id = ?
                """,
                (tenant_id, destination_id),
            ).fetchone()
        if row is None:
            return None
        return DeltaWatermark(
            observed_at=str(row["observed_at"]),
            batch_id=str(row["batch_id"]),
            updated_at=str(row["updated_at"]),
        )

    def set_watermark(self, tenant_id: str, destination_id: str, *, observed_at: str, batch_id: str) -> None:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delta_stream_watermarks (tenant_id, destination_id, observed_at, batch_id, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, destination_id) DO UPDATE SET
                    observed_at = excluded.observed_at,
                    batch_id = excluded.batch_id,
                    updated_at = excluded.updated_at
                """,
                (tenant_id, destination_id, observed_at, batch_id, now),
            )


def default_delta_stream_store_path() -> Path:
    from agent_bom.delivery import default_delivery_store_path

    return default_delivery_store_path().with_name("delta_stream.db")


def compute_finding_deltas(
    *,
    tenant_id: str,
    prior: dict[str, FindingSnapshot],
    batch_findings: list[dict[str, Any]],
    resolved_canonical_ids: set[str],
    observed_at: str,
    batch_id: str,
    source: str,
) -> list[FindingDeltaEvent]:
    """Return new / changed / resolved delta events for one ingest batch."""
    events: list[FindingDeltaEvent] = []
    seen: set[str] = set()

    for finding in batch_findings:
        snap = FindingSnapshot.from_finding(finding, source=source)
        seen.add(snap.canonical_id)
        prior_row = prior.get(snap.canonical_id)
        if prior_row is None:
            events.append(
                FindingDeltaEvent(
                    kind="new",
                    tenant_id=tenant_id,
                    canonical_id=snap.canonical_id,
                    observed_at=observed_at,
                    batch_id=batch_id,
                    source=source,
                    finding=snap.finding,
                )
            )
            continue
        merged = dict(prior_row.finding)
        merged.update(snap.finding)
        merged_snap = FindingSnapshot.from_finding(merged, source=source)
        if prior_row.material_fields_changed(merged_snap):
            events.append(
                FindingDeltaEvent(
                    kind="changed",
                    tenant_id=tenant_id,
                    canonical_id=snap.canonical_id,
                    observed_at=observed_at,
                    batch_id=batch_id,
                    source=source,
                    finding=merged,
                )
            )

    for canonical_id in sorted(resolved_canonical_ids):
        if canonical_id in seen:
            continue
        prior_row = prior.get(canonical_id)
        if prior_row is None:
            continue
        resolved_finding = dict(prior_row.finding)
        resolved_finding["status"] = "resolved"
        resolved_finding["canonical_id"] = canonical_id
        events.append(
            FindingDeltaEvent(
                kind="resolved",
                tenant_id=tenant_id,
                canonical_id=canonical_id,
                observed_at=observed_at,
                batch_id=batch_id,
                source=source,
                finding=resolved_finding,
            )
        )

    return events


def needs_hub_prior_snapshots(*, reconcile_absent: bool) -> bool:
    """Return whether bulk ingest must walk current-state before writing."""
    if reconcile_absent:
        return True
    return load_delta_stream_destination() is not None


def capture_hub_snapshots(store: Any, tenant_id: str, *, source: str) -> dict[str, FindingSnapshot]:
    """Walk current-state findings for a tenant/source into diff snapshots."""
    snapshots: dict[str, FindingSnapshot] = {}
    list_page = getattr(store, "list_current_page", None)
    if not callable(list_page):
        return snapshots
    cursor: str | None = None
    while True:
        page, _total, next_cursor = list_page(
            tenant_id,
            limit=500,
            origin=None,
            cursor=cursor,
            include_total=cursor is None,
        )
        for row in page:
            if str(row.get("source") or "") != source:
                continue
            if str(row.get("status") or "open") not in ("open", "reopened"):
                continue
            snap = FindingSnapshot.from_finding(row, source=source)
            snapshots[snap.canonical_id] = snap
        if not next_cursor:
            break
        cursor = next_cursor
    return snapshots


def resolved_canonical_ids(prior: dict[str, FindingSnapshot], present: set[str]) -> set[str]:
    return {cid for cid in prior if cid not in present}


def _format_delta_payload(events: list[FindingDeltaEvent], *, fmt: DeltaFormat) -> dict[str, Any]:
    raw_events = [event.to_dict() for event in events]
    if fmt == "ocsf":
        from agent_bom.siem.delta_stream import delta_events_to_ocsf

        return {"format": "ocsf", "events": delta_events_to_ocsf(raw_events)}
    return {"format": "ndjson", "events": raw_events}


@runtime_checkable
class DeltaStreamConnector(Protocol):
    def emit_batch(
        self,
        tenant_id: str,
        events: list[FindingDeltaEvent],
        *,
        observed_at: str,
        batch_id: str,
    ) -> list[Any]: ...


class DeliveryDeltaStreamConnector:
    """Deliver delta batches via :class:`DeliveryClient`."""

    def __init__(
        self,
        destination: DeltaStreamDestination,
        *,
        delivery_client: DeliveryClient | None = None,
        watermark_store: DeltaStreamStore | None = None,
        memory_sink: InMemoryDeltaSink | None = None,
    ) -> None:
        if not destination.url.strip() and memory_sink is None:
            raise DeltaStreamError("delta stream destination url is required unless using InMemoryDeltaSink")
        self.destination = destination
        self._client = None if memory_sink is not None else (delivery_client or get_delivery_client())
        self._watermarks = watermark_store or DeltaStreamStore(default_delta_stream_store_path())
        self._sink = memory_sink

    def emit_batch(
        self,
        tenant_id: str,
        events: list[FindingDeltaEvent],
        *,
        observed_at: str,
        batch_id: str,
    ) -> list[Any]:
        if not events:
            return []
        payload = _format_delta_payload(events, fmt=self.destination.format)
        payload["tenant_id"] = tenant_id
        payload["batch_id"] = batch_id
        payload["observed_at"] = observed_at
        payload["event_count"] = len(events)
        if self._sink is not None:
            self._sink.record(payload)
            self._watermarks.set_watermark(
                tenant_id,
                self.destination.destination_id,
                observed_at=observed_at,
                batch_id=batch_id,
            )
            return [{"status": "delivered", "sink": "memory"}]

        delivery = Delivery(
            destination_id=self.destination.destination_id,
            payload=payload,
            event_type="finding_delta_batch",
            idempotency_key=f"{tenant_id}:{batch_id}:{self.destination.destination_id}",
        )
        if self._client is None:
            raise DeltaStreamError("delivery client unavailable")
        result = self._client.deliver(self.destination.to_delivery_destination(), delivery)
        if result.delivered:
            self._watermarks.set_watermark(
                tenant_id,
                self.destination.destination_id,
                observed_at=observed_at,
                batch_id=batch_id,
            )
        return [result]


def load_delta_stream_destination() -> DeltaStreamDestination | None:
    import os

    from agent_bom.config import (
        DELTA_STREAM_AUTH_SCHEME,
        DELTA_STREAM_AUTH_TOKEN,
        DELTA_STREAM_DESTINATION_ID,
        DELTA_STREAM_ENABLED,
        DELTA_STREAM_FORMAT,
        DELTA_STREAM_SIGNING_SECRET,
        DELTA_STREAM_URL,
    )

    raw_enabled = os.environ.get("AGENT_BOM_DELTA_STREAM_ENABLED")
    if raw_enabled is None or not str(raw_enabled).strip():
        enabled = DELTA_STREAM_ENABLED
    else:
        enabled = str(raw_enabled).strip().lower() in ("1", "true", "yes", "on")
    raw_url = os.environ.get("AGENT_BOM_DELTA_STREAM_URL")
    url = (raw_url if raw_url is not None else DELTA_STREAM_URL).strip()
    if not enabled:
        return None
    if not url:
        logger.warning("AGENT_BOM_DELTA_STREAM_ENABLED=1 but AGENT_BOM_DELTA_STREAM_URL is empty; skipping delta export")
        return None
    fmt: DeltaFormat = "ocsf" if DELTA_STREAM_FORMAT.strip().lower() == "ocsf" else "ndjson"
    return DeltaStreamDestination(
        destination_id=DELTA_STREAM_DESTINATION_ID or "delta-stream-default",
        url=url,
        format=fmt,
        auth_scheme=DELTA_STREAM_AUTH_SCHEME,
        auth_token=DELTA_STREAM_AUTH_TOKEN,
        signing_secret=DELTA_STREAM_SIGNING_SECRET,
    )


def emit_hub_finding_deltas_if_enabled(
    *,
    tenant_id: str,
    hub_store: Any,
    prior: dict[str, FindingSnapshot],
    batch_findings: list[dict[str, Any]],
    resolved_canonical_ids: set[str],
    observed_at: str,
    batch_id: str,
    source: str,
    connector: DeltaStreamConnector | None = None,
) -> list[Any]:
    """Compute and emit hub finding deltas when delta-stream export is enabled."""
    destination = load_delta_stream_destination()
    if destination is None and connector is None:
        return []
    events = compute_finding_deltas(
        tenant_id=tenant_id,
        prior=prior,
        batch_findings=batch_findings,
        resolved_canonical_ids=resolved_canonical_ids,
        observed_at=observed_at,
        batch_id=batch_id,
        source=source,
    )
    if not events:
        return []
    active = connector or DeliveryDeltaStreamConnector(destination)  # type: ignore[arg-type]
    return active.emit_batch(tenant_id, events, observed_at=observed_at, batch_id=batch_id)


__all__ = [
    "DeltaEventKind",
    "DeltaFormat",
    "DeltaStreamDestination",
    "DeltaStreamError",
    "DeltaStreamStore",
    "DeltaWatermark",
    "DeliveryDeltaStreamConnector",
    "FindingDeltaEvent",
    "FindingSnapshot",
    "InMemoryDeltaSink",
    "needs_hub_prior_snapshots",
    "capture_hub_snapshots",
    "compute_finding_deltas",
    "default_delta_stream_store_path",
    "emit_hub_finding_deltas_if_enabled",
    "load_delta_stream_destination",
    "resolved_canonical_ids",
]
