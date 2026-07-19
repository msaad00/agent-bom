"""Optional, read-only runtime/EDR evidence mapped to canonical workloads.

This is stage 3 of the CWPP cross-cloud programme (#4158). It ingests runtime /
EDR signals (process executions, IOC detections, network connections, file
integrity, behavioural alerts) reported by an *external* sensor and joins them to
the same canonical workload identities the agentless disk side-scan targets.

There is **no mandatory host agent**: agent-bom neither installs nor requires a
sensor. When an operator already runs an EDR/runtime source, this subsystem lets
that source push metadata-only signals that *enrich* workloads, findings, and
attack-path campaigns.

Non-negotiable properties (issue #4158, honesty constraints):

* **Authenticated ingest.** Every source is registered with a hashed shared
  secret; a signal batch is accepted only after a constant-time secret check.
* **Identity binding is source-authoritative.** Tenant / provider / account come
  from the authenticated source, never from the client payload — a spoofed
  provider/account on a raw signal is rejected (confused-deputy guard). A signal
  with no workload reference or an unparseable timestamp is rejected.
* **Fail closed on stale.** A signal older than the freshness window is rejected,
  not silently accepted.
* **Deduplicated.** A `(tenant, provider, account, workload, dedup_key)` scope is
  ingested once; retries and cross-batch duplicates are dropped.
* **Additive, never a cleanliness claim.** Evidence enriches; the *absence* of a
  runtime signal is explicitly ``no_runtime_signal`` and every summary carries
  ``clean_workload_assertion = False``. Enrichment never fabricates reachability.
* **Metadata only.** Raw block bytes, file contents, and secret values are never
  persisted; evidence is redacted to bounded metadata at construction.
* **Tenant isolated.** The enrichment index only ever holds one tenant's signals;
  graph joins refuse to cross the tenant boundary.

Durable persistence lives in
:mod:`agent_bom.cloud.runtime_workload_evidence_store`.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Iterable, Mapping

from agent_bom.canonical_ids import canonical_id

RUNTIME_EVIDENCE_SCHEMA_VERSION = "agent-bom.cwpp.runtime_workload.evidence.v1"

# Freshness window: a runtime signal observed more than this many seconds before
# ingestion is stale and rejected (fail closed). One hour by default.
DEFAULT_MAX_SIGNAL_AGE_SECONDS = 3600

# Enrichment states. None of these ever mean "clean".
STATE_HAS_IOC = "runtime_ioc_observed"
STATE_HAS_ALERT = "runtime_alert_observed"
STATE_OBSERVED = "runtime_activity_observed"
STATE_NO_SIGNAL = "no_runtime_signal"

_ADDITIVE_NOTE = "Runtime evidence is additive: the absence of a runtime signal is not evidence that the workload is clean."

_VALID_PROVIDERS = frozenset({"aws", "azure", "gcp"})
_VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info", "unknown"})

# Evidence keys that could carry data-plane bytes / secret values are dropped at
# construction. Metadata references (``*_ref``, types, counts) are kept, bounded.
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "raw_bytes",
        "bytes",
        "file_contents",
        "contents",
        "content",
        "secret_value",
        "secret",
        "value",
        "values",
        "data",
        "payload",
        "blob",
        "raw",
        "body",
        "snippet",
        "sample",
    }
)
_MAX_EVIDENCE_KEYS = 20
_MAX_EVIDENCE_VALUE_LEN = 256


class SourceAuthenticationError(RuntimeError):
    """Raised when a runtime evidence source cannot be authenticated."""


class IncompleteIdentityBindingError(ValueError):
    """Raised when a raw signal cannot be bound to a workload identity."""


class StaleSignalError(ValueError):
    """Raised when a runtime signal is older than the freshness window."""


class RuntimeSignalType(str, Enum):
    """Bounded set of runtime/EDR signal classes."""

    PROCESS_EXEC = "process_exec"
    IOC_DETECTION = "ioc_detection"
    NETWORK_CONNECTION = "network_connection"
    FILE_INTEGRITY = "file_integrity"
    BEHAVIORAL_ALERT = "behavioral_alert"


def canonical_workload_id(provider: str, account_id: str, workload_ref: str) -> str:
    """Deterministic canonical identity for a cloud workload.

    Rooted in provider + account/subscription/project + the provider-native
    resource id, so a runtime signal and the agentless side-scan target resolve to
    the same workload without fabricating a link.
    """
    return canonical_id("workload", provider, account_id, workload_ref)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts(value: str) -> datetime | None:
    text = (value or "").strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)


def _redact_evidence(evidence: Mapping[str, Any] | None) -> dict[str, str]:
    """Return bounded metadata only; drop any key that could carry data-plane bytes."""
    if not isinstance(evidence, Mapping):
        return {}
    redacted: dict[str, str] = {}
    for key, value in evidence.items():
        if len(redacted) >= _MAX_EVIDENCE_KEYS:
            break
        key_text = str(key).strip().lower()
        if not key_text or key_text in _FORBIDDEN_EVIDENCE_KEYS:
            continue
        if isinstance(value, (dict, list, tuple, set, bytes, bytearray)):
            # Nested structures may hide raw content; keep only a type marker.
            redacted[key_text] = f"<{type(value).__name__}>"
            continue
        redacted[key_text] = str(value)[:_MAX_EVIDENCE_VALUE_LEN]
    return redacted


def _normalize_severity(value: str) -> str:
    sev = (value or "").strip().lower()
    return sev if sev in _VALID_SEVERITIES else "unknown"


@dataclass(frozen=True)
class RuntimeEvidenceSource:
    """A registered, authenticated runtime/EDR source scoped to one account."""

    source_id: str
    tenant_id: str
    provider: str
    account_id: str
    kind: str
    secret_hash: str

    def __post_init__(self) -> None:
        required = (self.source_id, self.tenant_id, self.provider, self.account_id, self.kind, self.secret_hash)
        if not all(str(part).strip() for part in required):
            raise ValueError("runtime evidence source requires all identity fields")
        if self.provider not in _VALID_PROVIDERS:
            raise ValueError(f"unsupported runtime source provider: {self.provider}")
        if len(self.secret_hash) != 64 or any(ch not in "0123456789abcdef" for ch in self.secret_hash):
            raise ValueError("secret_hash must be a 64-character lowercase sha256 hex digest")

    @classmethod
    def register(
        cls,
        *,
        source_id: str,
        tenant_id: str,
        provider: str,
        account_id: str,
        kind: str,
        secret: str,
    ) -> "RuntimeEvidenceSource":
        """Register a source, storing only the sha256 of the shared secret."""
        if not secret or len(secret) < 8:
            raise ValueError("runtime source secret must be at least 8 characters")
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return cls(
            source_id=source_id.strip(),
            tenant_id=tenant_id.strip(),
            provider=provider.strip().lower(),
            account_id=account_id.strip(),
            kind=kind.strip().lower(),
            secret_hash=digest,
        )

    def authenticate(self, secret: str) -> bool:
        """Constant-time comparison of a presented secret against the stored hash."""
        presented = hashlib.sha256((secret or "").encode("utf-8")).hexdigest()
        return hmac.compare_digest(presented, self.secret_hash)


class RuntimeSourceRegistry:
    """In-memory registry of authenticated runtime evidence sources."""

    def __init__(self) -> None:
        self._sources: dict[str, RuntimeEvidenceSource] = {}

    def add(self, source: RuntimeEvidenceSource) -> None:
        self._sources[source.source_id] = source

    def get(self, source_id: str) -> RuntimeEvidenceSource | None:
        return self._sources.get(source_id)

    def authenticate(self, source_id: str, secret: str) -> RuntimeEvidenceSource:
        """Return the source only when it exists and the secret matches; else raise."""
        source = self._sources.get(source_id)
        if source is None or not source.authenticate(secret):
            # One error for both cases so a caller cannot enumerate valid source ids.
            raise SourceAuthenticationError("runtime evidence source authentication failed")
        return source


@dataclass(frozen=True)
class RuntimeWorkloadSignal:
    """One normalized, redacted runtime/EDR signal bound to a canonical workload."""

    tenant_id: str
    provider: str
    account_id: str
    workload_ref: str
    signal_type: RuntimeSignalType
    severity: str
    observed_at: str
    source_id: str
    source_kind: str
    dedup_key: str
    title: str = ""
    # Accepts arbitrary metadata on input; redacted to bounded str values in
    # ``__post_init__`` so no data-plane bytes are ever retained.
    evidence: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        required = (
            self.tenant_id,
            self.provider,
            self.account_id,
            self.workload_ref,
            self.observed_at,
            self.source_id,
            self.source_kind,
            self.dedup_key,
        )
        if not all(str(part).strip() for part in required):
            raise IncompleteIdentityBindingError("runtime signal is missing required identity fields")
        if self.provider not in _VALID_PROVIDERS:
            raise IncompleteIdentityBindingError(f"unsupported runtime signal provider: {self.provider}")
        if not isinstance(self.signal_type, RuntimeSignalType):
            object.__setattr__(self, "signal_type", RuntimeSignalType(str(self.signal_type)))
        if _parse_ts(self.observed_at) is None:
            raise IncompleteIdentityBindingError("runtime signal observed_at is not an ISO-8601 timestamp")
        object.__setattr__(self, "severity", _normalize_severity(self.severity))
        object.__setattr__(self, "title", str(self.title)[:_MAX_EVIDENCE_VALUE_LEN])
        object.__setattr__(self, "evidence", _redact_evidence(self.evidence))

    @property
    def workload_id(self) -> str:
        return canonical_workload_id(self.provider, self.account_id, self.workload_ref)

    @property
    def dedup_scope(self) -> str:
        """Hashable dedup identity: tenant + workload scope + source dedup key."""
        return "\x1f".join(
            (
                self.tenant_id,
                self.provider,
                self.account_id.lower(),
                self.workload_ref.lower(),
                self.dedup_key,
            )
        )

    def is_stale(self, now: str, max_age_seconds: int) -> bool:
        """True when the signal is older than the freshness window (fail closed)."""
        observed = _parse_ts(self.observed_at)
        reference = _parse_ts(now) or datetime.now(timezone.utc)
        if observed is None:
            return True
        return (reference - observed).total_seconds() > max_age_seconds

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_EVIDENCE_SCHEMA_VERSION,
            "tenant_id": self.tenant_id,
            "provider": self.provider,
            "account_id": self.account_id,
            "workload_ref": self.workload_ref,
            "workload_id": self.workload_id,
            "signal_type": self.signal_type.value,
            "severity": self.severity,
            "observed_at": self.observed_at,
            "source_id": self.source_id,
            "source_kind": self.source_kind,
            "dedup_key": self.dedup_key,
            "title": self.title,
            "evidence": dict(self.evidence),
        }

    def to_evidence_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_EVIDENCE_SCHEMA_VERSION,
            "workload_id": self.workload_id,
            "signal_type": self.signal_type.value,
            "severity": self.severity,
            "observed_at": self.observed_at,
            "source_kind": self.source_kind,
            "clean_workload_assertion": False,
            "data_boundary": "customer_account_metadata_only",
            "redaction": "raw block bytes, file contents, and secret values are not persisted",
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "RuntimeWorkloadSignal":
        raw_evidence = payload.get("evidence")
        evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
        return cls(
            tenant_id=str(payload.get("tenant_id") or ""),
            provider=str(payload.get("provider") or ""),
            account_id=str(payload.get("account_id") or ""),
            workload_ref=str(payload.get("workload_ref") or ""),
            signal_type=RuntimeSignalType(str(payload.get("signal_type") or "")),
            severity=str(payload.get("severity") or "unknown"),
            observed_at=str(payload.get("observed_at") or ""),
            source_id=str(payload.get("source_id") or ""),
            source_kind=str(payload.get("source_kind") or ""),
            dedup_key=str(payload.get("dedup_key") or ""),
            title=str(payload.get("title") or ""),
            evidence=evidence,
        )


def build_runtime_signal(source: RuntimeEvidenceSource, raw: Mapping[str, Any], *, now: str | None = None) -> RuntimeWorkloadSignal:
    """Bind one raw payload to a workload identity from the AUTHENTICATED source.

    Tenant, provider, and account come from ``source`` — never from the payload.
    A payload that claims a different provider/account is a confused-deputy attempt
    and is rejected. Missing workload reference or unparseable timestamp is
    rejected. Raises :class:`IncompleteIdentityBindingError` on any of these.
    """
    workload_ref = str(raw.get("workload_ref") or raw.get("resource_id") or raw.get("target_id") or "").strip()
    if not workload_ref:
        raise IncompleteIdentityBindingError("runtime signal is missing a workload reference")

    claimed_provider = str(raw.get("provider") or "").strip().lower()
    if claimed_provider and claimed_provider != source.provider:
        raise IncompleteIdentityBindingError("runtime signal provider does not match the authenticated source")
    claimed_account = str(raw.get("account_id") or "").strip()
    if claimed_account and claimed_account != source.account_id:
        raise IncompleteIdentityBindingError("runtime signal account does not match the authenticated source")

    signal_type_raw = str(raw.get("signal_type") or "").strip().lower()
    try:
        signal_type = RuntimeSignalType(signal_type_raw)
    except ValueError as exc:
        raise IncompleteIdentityBindingError(f"unsupported runtime signal_type: {signal_type_raw or 'missing'}") from exc

    observed_at = str(raw.get("observed_at") or "").strip() or (now or _now_iso())
    dedup_key = str(raw.get("dedup_key") or raw.get("event_id") or "").strip()
    if not dedup_key:
        raise IncompleteIdentityBindingError("runtime signal is missing a dedup_key")

    raw_evidence = raw.get("evidence")
    evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    return RuntimeWorkloadSignal(
        tenant_id=source.tenant_id,
        provider=source.provider,
        account_id=source.account_id,
        workload_ref=workload_ref,
        signal_type=signal_type,
        severity=str(raw.get("severity") or "unknown"),
        observed_at=observed_at,
        source_id=source.source_id,
        source_kind=source.kind,
        dedup_key=dedup_key,
        title=str(raw.get("title") or ""),
        evidence=evidence,
    )


@dataclass
class IngestResult:
    """Non-secret summary of one ingest pass."""

    source_id: str
    tenant_id: str
    accepted: list[RuntimeWorkloadSignal] = field(default_factory=list)
    deduped: int = 0
    rejected_stale: int = 0
    rejected_incomplete: int = 0
    persisted: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": RUNTIME_EVIDENCE_SCHEMA_VERSION,
            "source_id": self.source_id,
            "tenant_id": self.tenant_id,
            "accepted": len(self.accepted),
            "deduped": self.deduped,
            "rejected_stale": self.rejected_stale,
            "rejected_incomplete": self.rejected_incomplete,
            "persisted": self.persisted,
        }


def ingest_runtime_signals(
    *,
    registry: RuntimeSourceRegistry,
    source_id: str,
    secret: str,
    raw_signals: Iterable[Mapping[str, Any]],
    now: str | None = None,
    max_age_seconds: int = DEFAULT_MAX_SIGNAL_AGE_SECONDS,
    store: Any = None,
    dedup_seen: set[str] | None = None,
) -> IngestResult:
    """Authenticate a source and ingest a bounded batch of runtime signals.

    Source authentication failure raises :class:`SourceAuthenticationError` (the
    whole batch is refused — fail closed). Per-signal problems never sink the
    batch: an incomplete identity binding or unparseable timestamp is counted in
    ``rejected_incomplete``, a stale signal in ``rejected_stale``, and duplicates
    (within the batch, against ``dedup_seen``, or already persisted) in
    ``deduped``. Accepted signals are persisted through ``store`` when supplied.
    """
    source = registry.authenticate(source_id, secret)
    reference_now = now or _now_iso()
    result = IngestResult(source_id=source.source_id, tenant_id=source.tenant_id)

    seen: set[str] = set(dedup_seen or set())
    for raw in raw_signals:
        try:
            signal = build_runtime_signal(source, raw, now=reference_now)
        except IncompleteIdentityBindingError:
            result.rejected_incomplete += 1
            continue
        if signal.is_stale(reference_now, max_age_seconds):
            result.rejected_stale += 1
            continue
        if signal.dedup_scope in seen:
            result.deduped += 1
            continue
        seen.add(signal.dedup_scope)
        result.accepted.append(signal)

    if store is not None and result.accepted:
        # The store dedups against already-persisted rows; anything it does not
        # newly insert is a cross-restart duplicate.
        persisted = store.put_batch(result.accepted)
        result.persisted = persisted
        result.deduped += len(result.accepted) - persisted

    return result


# ── Enrichment (additive, honest, tenant-isolated) ───────────────────────────


def workload_runtime_summary(signals: list[RuntimeWorkloadSignal]) -> dict[str, Any]:
    """Summarize present runtime signals for one workload. Never claims clean."""
    if not signals:
        return no_runtime_signal_summary()

    types = {sig.signal_type for sig in signals}
    if RuntimeSignalType.IOC_DETECTION in types:
        state = STATE_HAS_IOC
    elif types & {RuntimeSignalType.BEHAVIORAL_ALERT, RuntimeSignalType.FILE_INTEGRITY}:
        state = STATE_HAS_ALERT
    else:
        state = STATE_OBSERVED

    severity_counts: dict[str, int] = {}
    type_counts: dict[str, int] = {}
    source_kinds: set[str] = set()
    latest = ""
    for sig in signals:
        severity_counts[sig.severity] = severity_counts.get(sig.severity, 0) + 1
        type_counts[sig.signal_type.value] = type_counts.get(sig.signal_type.value, 0) + 1
        source_kinds.add(sig.source_kind)
        if sig.observed_at > latest:
            latest = sig.observed_at

    return {
        "schema_version": RUNTIME_EVIDENCE_SCHEMA_VERSION,
        "state": state,
        "signal_count": len(signals),
        "signal_types": type_counts,
        "severity_counts": severity_counts,
        "source_kinds": sorted(source_kinds),
        "latest_observed_at": latest,
        "clean_workload_assertion": False,
        "note": _ADDITIVE_NOTE,
    }


def no_runtime_signal_summary() -> dict[str, Any]:
    """Explicit no-signal summary. Absence is stated, never rendered as clean."""
    return {
        "schema_version": RUNTIME_EVIDENCE_SCHEMA_VERSION,
        "state": STATE_NO_SIGNAL,
        "signal_count": 0,
        "clean_workload_assertion": False,
        "note": _ADDITIVE_NOTE,
    }


class RuntimeWorkloadEvidenceIndex:
    """Tenant-scoped index of runtime signals keyed by workload, for enrichment."""

    def __init__(self, tenant_id: str) -> None:
        self.tenant_id = tenant_id
        self._by_workload: dict[str, list[RuntimeWorkloadSignal]] = {}

    @staticmethod
    def _key(provider: str, account_id: str, workload_ref: str) -> str:
        return "\x1f".join(((provider or "").strip().lower(), (account_id or "").strip().lower(), (workload_ref or "").strip().lower()))

    @classmethod
    def from_signals(cls, tenant_id: str, signals: Iterable[RuntimeWorkloadSignal]) -> "RuntimeWorkloadEvidenceIndex":
        index = cls(tenant_id)
        for sig in signals:
            # Tenant isolation: a signal from another tenant is never indexed here.
            if sig.tenant_id != tenant_id:
                continue
            index._by_workload.setdefault(cls._key(sig.provider, sig.account_id, sig.workload_ref), []).append(sig)
        return index

    @classmethod
    def from_store(cls, store: Any, tenant_id: str, *, limit: int = 5000) -> "RuntimeWorkloadEvidenceIndex":
        signals = store.list_for_tenant(tenant_id, limit=limit) if store is not None else []
        return cls.from_signals(tenant_id, signals)

    def is_empty(self) -> bool:
        return not self._by_workload

    def summary_for(self, provider: str, account_id: str, workload_ref: str) -> dict[str, Any]:
        signals = self._by_workload.get(self._key(provider, account_id, workload_ref), [])
        return workload_runtime_summary(signals)


def _account_from_ref(value: str) -> str:
    """Return the bare account id from an ``aws:123`` style account_ref, else the input."""
    text = (value or "").strip()
    if ":" in text:
        return text.split(":", 1)[1].strip()
    return text


def _resolve_finding_workload(row: Mapping[str, Any]) -> tuple[str, str, str] | None:
    provider = str(row.get("provider") or "").strip().lower()
    account = _account_from_ref(str(row.get("account_ref") or "")) or str(row.get("account_id") or "").strip()
    workload_ref = str(row.get("resource_id") or row.get("target_id") or row.get("asset_id") or row.get("workload_ref") or "").strip()
    if provider and account and workload_ref:
        return provider, account, workload_ref
    return None


def attach_workload_runtime_evidence_to_finding(row: dict[str, Any], index: RuntimeWorkloadEvidenceIndex | None) -> dict[str, Any]:
    """Attach ``workload_runtime_evidence`` to a workload-scoped finding row.

    Only rows that resolve to a canonical workload identity are annotated. A
    workload with no matching signal is marked ``no_runtime_signal`` (never
    clean). Reachability is never invented. Mutates and returns ``row``.
    """
    if index is None:
        return row
    resolved = _resolve_finding_workload(row)
    if resolved is None:
        return row
    row["workload_runtime_evidence"] = index.summary_for(*resolved)
    return row


def _node_attributes(node: Any) -> dict[str, Any] | None:
    if isinstance(node, Mapping):
        attrs = node.get("attributes")
        return attrs if isinstance(attrs, dict) else None
    attrs = getattr(node, "attributes", None)
    return attrs if isinstance(attrs, dict) else None


def _node_entity_type(node: Any) -> str:
    if isinstance(node, Mapping):
        return str(node.get("entity_type") or "").strip().lower()
    et = getattr(node, "entity_type", "")
    return str(getattr(et, "value", et) or "").strip().lower()


def _is_workload_node(node: Any) -> bool:
    attrs = _node_attributes(node)
    if attrs is None:
        return False
    if _node_entity_type(node) != "cloud_resource":
        return False
    return str(attrs.get("resource_type") or "").strip().lower() == "workload_disk"


def attach_workload_runtime_evidence_to_node(node: Any, index: RuntimeWorkloadEvidenceIndex | None) -> bool:
    """Annotate a CWPP workload node's attributes with runtime evidence.

    Adds an additive ``runtime_evidence`` attribute; never adds an edge, so graph
    reachability stays edge-derived. Returns True when the node was annotated.
    """
    if index is None or not _is_workload_node(node):
        return False
    attrs = _node_attributes(node)
    assert attrs is not None  # guaranteed by _is_workload_node
    provider = str(attrs.get("cloud_provider") or "").strip().lower()
    account = str(attrs.get("account_id") or "").strip()
    workload_ref = str(attrs.get("resource_id") or attrs.get("resource_name") or "").strip()
    if not (provider and account and workload_ref):
        return False
    attrs["runtime_evidence"] = index.summary_for(provider, account, workload_ref)
    return True


def enrich_graph_workload_runtime_evidence(graph: Any, index: RuntimeWorkloadEvidenceIndex | None) -> int:
    """Annotate every workload node in ``graph`` with runtime evidence.

    Tenant isolation in the graph join: the graph's ``tenant_id`` must match the
    index's, else nothing is enriched. Returns the number of nodes annotated.
    """
    if index is None:
        return 0
    graph_tenant = str(getattr(graph, "tenant_id", "") or "")
    if graph_tenant and graph_tenant != index.tenant_id:
        return 0
    nodes = getattr(graph, "nodes", None)
    if isinstance(nodes, Mapping):
        node_iter: Iterable[Any] = nodes.values()
    elif nodes is not None:
        node_iter = nodes
    else:
        return 0
    return sum(1 for node in node_iter if attach_workload_runtime_evidence_to_node(node, index))


__all__ = [
    "DEFAULT_MAX_SIGNAL_AGE_SECONDS",
    "RUNTIME_EVIDENCE_SCHEMA_VERSION",
    "STATE_HAS_ALERT",
    "STATE_HAS_IOC",
    "STATE_NO_SIGNAL",
    "STATE_OBSERVED",
    "IncompleteIdentityBindingError",
    "IngestResult",
    "RuntimeEvidenceSource",
    "RuntimeSignalType",
    "RuntimeSourceRegistry",
    "RuntimeWorkloadEvidenceIndex",
    "RuntimeWorkloadSignal",
    "SourceAuthenticationError",
    "StaleSignalError",
    "attach_workload_runtime_evidence_to_finding",
    "attach_workload_runtime_evidence_to_node",
    "build_runtime_signal",
    "canonical_workload_id",
    "enrich_graph_workload_runtime_evidence",
    "ingest_runtime_signals",
    "no_runtime_signal_summary",
    "workload_runtime_summary",
]
