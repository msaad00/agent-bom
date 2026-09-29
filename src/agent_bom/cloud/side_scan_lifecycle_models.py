"""Side-scan execution record, cleanup ownership and temporary-resource contracts."""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Mapping, cast

from .side_scan_lifecycle_status import (
    _CLEANUP_TRANSITIONS,
    _EXECUTION_TRANSITIONS,
    _PHASES,
    _RESOURCE_TRANSITIONS,
    EVIDENCE_SCHEMA_VERSION,
    LIFECYCLE_SCHEMA_VERSION,
    CleanupStatus,
    ExecutionStatus,
    SideScanProvider,
    TemporaryResourceStatus,
)


@dataclass(frozen=True)
class SideScanCleanupOwnership:
    """Deterministic ownership proof required before cleanup is attempted."""

    execution_id: str
    owner_id: str
    scope_hash: str

    def __post_init__(self) -> None:
        try:
            uuid.UUID(self.execution_id)
        except ValueError as exc:
            raise ValueError("cleanup ownership execution id must be a UUID") from exc
        hex_chars = frozenset("0123456789abcdef")
        if (
            len(self.owner_id) != 24
            or len(self.scope_hash) != 24
            or not set(self.owner_id) <= hex_chars
            or not set(self.scope_hash) <= hex_chars
        ):
            raise ValueError("cleanup owner and scope ids must be 24-character lowercase hex")

    def required_tags(self) -> dict[str, str]:
        return {
            "agent-bom-sidescan": "true",
            "agent-bom-sidescan-owner": self.owner_id,
            "agent-bom-sidescan-scope": self.scope_hash,
            "agent-bom-sidescan-execution": self.execution_id,
        }

    def owns(self, resource_tags: Mapping[str, str]) -> bool:
        """Return true only when every ownership tag matches exactly."""
        return all(resource_tags.get(key) == value for key, value in self.required_tags().items())

    def to_dict(self) -> dict[str, object]:
        return {
            "execution_id": self.execution_id,
            "owner_id": self.owner_id,
            "scope_hash": self.scope_hash,
            "required_tags": self.required_tags(),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "SideScanCleanupOwnership":
        return cls(
            execution_id=str(payload.get("execution_id") or ""),
            owner_id=str(payload.get("owner_id") or ""),
            scope_hash=str(payload.get("scope_hash") or ""),
        )


@dataclass(frozen=True)
class SideScanTemporaryResource:
    """Metadata for one temporary resource; never contains data-plane bytes."""

    kind: str
    resource_id: str
    status: TemporaryResourceStatus
    ownership_tags: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.kind.strip() or not self.resource_id.strip():
            raise ValueError("temporary resource kind and id are required")

    def to_dict(self) -> dict[str, object]:
        return {
            "kind": self.kind,
            "resource_id": self.resource_id,
            "status": self.status.value,
            "ownership_tags": dict(self.ownership_tags),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "SideScanTemporaryResource":
        raw_tags = payload.get("ownership_tags")
        tags = {str(key): str(value) for key, value in raw_tags.items()} if isinstance(raw_tags, dict) else {}
        return cls(
            kind=str(payload.get("kind") or ""),
            resource_id=str(payload.get("resource_id") or ""),
            status=TemporaryResourceStatus(str(payload.get("status") or "")),
            ownership_tags=tags,
        )


@dataclass(frozen=True)
class SideScanExecutionRecord:
    """Versioned, restart-safe execution state and metadata-only evidence."""

    execution_id: str
    idempotency_key: str
    tenant_id: str
    provider: SideScanProvider
    account_id: str
    target_id: str
    collector_id: str
    cleanup_ownership: SideScanCleanupOwnership
    status: ExecutionStatus = ExecutionStatus.QUEUED
    phase: str = "requested"
    cleanup_status: CleanupStatus = CleanupStatus.NOT_STARTED
    resources: tuple[SideScanTemporaryResource, ...] = ()
    package_count: int = 0
    vulnerability_count: int = 0
    secret_count: int = 0
    config_finding_count: int = 0
    ioc_finding_count: int = 0
    failure_code: str = ""
    warning_codes: tuple[str, ...] = ()
    state_version: int = 1
    created_at: str = ""
    updated_at: str = ""
    request_fingerprint: str = ""
    schema_version: str = field(default=LIFECYCLE_SCHEMA_VERSION, init=False)

    def __post_init__(self) -> None:
        required = (
            self.execution_id,
            self.idempotency_key,
            self.tenant_id,
            self.provider,
            self.account_id,
            self.target_id,
            self.collector_id,
            self.created_at,
            self.updated_at,
        )
        if not all(str(value).strip() for value in required):
            raise ValueError("side-scan execution scope and timestamps are required")
        if self.request_fingerprint and (
            len(self.request_fingerprint) != 64 or any(c not in "0123456789abcdef" for c in self.request_fingerprint)
        ):
            raise ValueError("request_fingerprint must be a SHA-256 hex digest")
        if self.phase not in _PHASES:
            raise ValueError(f"unsupported side-scan phase: {self.phase}")
        counts = (
            self.package_count,
            self.vulnerability_count,
            self.secret_count,
            self.config_finding_count,
            self.ioc_finding_count,
            self.state_version,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise ValueError("side-scan counts and state version must be non-negative integers")
        if self.state_version < 1:
            raise ValueError("state_version must be at least 1")
        if self.cleanup_ownership.execution_id != self.execution_id:
            raise ValueError("cleanup ownership must match the execution id")
        if self.provider not in {"aws", "azure", "gcp"}:
            raise ValueError("unsupported side-scan provider")
        if self.failure_code and (len(self.failure_code) > 128 or any(char.isspace() for char in self.failure_code)):
            raise ValueError("failure_code must be a bounded machine-readable code")
        if any(len(code) > 128 or not code or any(char.isspace() for char in code) for code in self.warning_codes):
            raise ValueError("warning_codes must be bounded machine-readable codes")

    @property
    def disposition(self) -> str:
        """Return evidence completeness without ever claiming workload cleanliness."""
        if self.status is ExecutionStatus.SCAN_COMPLETE and self.cleanup_status is CleanupStatus.COMPLETE:
            return "complete"
        if self.status in {ExecutionStatus.SCAN_COMPLETE, ExecutionStatus.PARTIAL}:
            return "partial"
        return "unevaluable"

    def transition(
        self,
        *,
        status: ExecutionStatus | None = None,
        phase: str | None = None,
        cleanup_status: CleanupStatus | None = None,
        package_count: int | None = None,
        vulnerability_count: int | None = None,
        secret_count: int | None = None,
        config_finding_count: int | None = None,
        ioc_finding_count: int | None = None,
        failure_code: str | None = None,
        warning_codes: tuple[str, ...] | None = None,
        now: str | None = None,
    ) -> "SideScanExecutionRecord":
        """Advance state with optimistic-version semantics; repeated writes are no-ops."""
        next_status = status or self.status
        next_cleanup = cleanup_status or self.cleanup_status
        if next_status not in _EXECUTION_TRANSITIONS[self.status]:
            raise ValueError(f"invalid execution transition: {self.status.value} -> {next_status.value}")
        if next_cleanup not in _CLEANUP_TRANSITIONS[self.cleanup_status]:
            raise ValueError(f"invalid cleanup transition: {self.cleanup_status.value} -> {next_cleanup.value}")
        if next_cleanup is CleanupStatus.COMPLETE and self.cleanup_candidates():
            raise ValueError("cleanup cannot complete while owned temporary resources remain")
        next_phase = phase or self.phase
        next_package_count = self.package_count if package_count is None else package_count
        next_vulnerability_count = self.vulnerability_count if vulnerability_count is None else vulnerability_count
        next_secret_count = self.secret_count if secret_count is None else secret_count
        next_config_finding_count = self.config_finding_count if config_finding_count is None else config_finding_count
        next_ioc_finding_count = self.ioc_finding_count if ioc_finding_count is None else ioc_finding_count
        next_failure_code = self.failure_code if failure_code is None else failure_code
        next_warning_codes = self.warning_codes if warning_codes is None else warning_codes
        if (
            next_status is self.status
            and next_phase == self.phase
            and next_cleanup is self.cleanup_status
            and next_package_count == self.package_count
            and next_vulnerability_count == self.vulnerability_count
            and next_secret_count == self.secret_count
            and next_config_finding_count == self.config_finding_count
            and next_ioc_finding_count == self.ioc_finding_count
            and next_failure_code == self.failure_code
            and next_warning_codes == self.warning_codes
        ):
            return self
        return replace(
            self,
            status=next_status,
            phase=next_phase,
            cleanup_status=next_cleanup,
            package_count=next_package_count,
            vulnerability_count=next_vulnerability_count,
            secret_count=next_secret_count,
            config_finding_count=next_config_finding_count,
            ioc_finding_count=next_ioc_finding_count,
            failure_code=next_failure_code,
            warning_codes=next_warning_codes,
            state_version=self.state_version + 1,
            updated_at=now or _now(),
        )

    def register_resource(self, resource: SideScanTemporaryResource, *, now: str | None = None) -> "SideScanExecutionRecord":
        """Register an owned resource once; exact retries return the same record."""
        if not self.cleanup_ownership.owns(resource.ownership_tags):
            raise ValueError("temporary resource does not match cleanup ownership")
        if dict(resource.ownership_tags) != self.cleanup_ownership.required_tags():
            raise ValueError("only cleanup ownership tags may be persisted")
        for existing in self.resources:
            if existing.kind == resource.kind and existing.resource_id == resource.resource_id:
                if existing == resource:
                    return self
                raise ValueError("temporary resource identity already has different state")
        return replace(
            self,
            resources=(*self.resources, resource),
            state_version=self.state_version + 1,
            updated_at=now or _now(),
        )

    def mark_resource_cleanup(
        self,
        resource_id: str,
        *,
        status: TemporaryResourceStatus,
        now: str | None = None,
    ) -> "SideScanExecutionRecord":
        """Update cleanup state idempotently for one owned resource."""
        updated: list[SideScanTemporaryResource] = []
        found = False
        changed = False
        for resource in self.resources:
            if resource.resource_id != resource_id:
                updated.append(resource)
                continue
            found = True
            if not self.cleanup_ownership.owns(resource.ownership_tags):
                raise ValueError("temporary resource does not match cleanup ownership")
            if status not in _RESOURCE_TRANSITIONS[resource.status]:
                raise ValueError(f"invalid resource cleanup transition: {resource.status.value} -> {status.value}")
            if resource.status is status:
                updated.append(resource)
            else:
                updated.append(replace(resource, status=status))
                changed = True
        if not found:
            raise KeyError(resource_id)
        if not changed:
            return self
        return replace(
            self,
            resources=tuple(updated),
            state_version=self.state_version + 1,
            updated_at=now or _now(),
        )

    def cleanup_candidates(self) -> tuple[SideScanTemporaryResource, ...]:
        """Return only owned resources still requiring deletion."""
        return tuple(
            resource
            for resource in self.resources
            if resource.status is not TemporaryResourceStatus.DELETED and self.cleanup_ownership.owns(resource.ownership_tags)
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "execution_id": self.execution_id,
            "idempotency_key": self.idempotency_key,
            "tenant_id": self.tenant_id,
            "provider": self.provider,
            "account_id": self.account_id,
            "target_id": self.target_id,
            "collector_id": self.collector_id,
            "status": self.status.value,
            "phase": self.phase,
            "cleanup_status": self.cleanup_status.value,
            "cleanup_ownership": self.cleanup_ownership.to_dict(),
            "resources": [resource.to_dict() for resource in self.resources],
            "counts": self._counts(),
            "failure_code": self.failure_code,
            "warning_codes": list(self.warning_codes),
            **({"request_fingerprint": self.request_fingerprint} if self.request_fingerprint else {}),
            "state_version": self.state_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def to_evidence_dict(self) -> dict[str, object]:
        return {
            "schema_version": EVIDENCE_SCHEMA_VERSION,
            "execution_id": self.execution_id,
            "provider": self.provider,
            "account_id": self.account_id,
            "target_id": self.target_id,
            "execution_status": self.status.value,
            "cleanup_status": self.cleanup_status.value,
            "disposition": self.disposition,
            "negative_result_scope": "scanned_disk_only" if self.disposition == "complete" else "unavailable",
            "clean_workload_assertion": False,
            **self._counts(),
            "failure_code": self.failure_code,
            "warning_codes": list(self.warning_codes),
            "data_boundary": "customer_account_metadata_only",
            "redaction": "raw block bytes, file contents, and secret values are not persisted",
            "updated_at": self.updated_at,
        }

    def _counts(self) -> dict[str, int]:
        return {
            "package_count": self.package_count,
            "vulnerability_count": self.vulnerability_count,
            "secret_count": self.secret_count,
            "config_finding_count": self.config_finding_count,
            "ioc_finding_count": self.ioc_finding_count,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, object]) -> "SideScanExecutionRecord":
        if payload.get("schema_version") != LIFECYCLE_SCHEMA_VERSION:
            raise ValueError("unsupported side-scan lifecycle schema")
        raw_counts = payload.get("counts")
        counts = raw_counts if isinstance(raw_counts, dict) else {}
        raw_resources = payload.get("resources")
        resources = (
            tuple(SideScanTemporaryResource.from_dict(item) for item in raw_resources if isinstance(item, dict))
            if isinstance(raw_resources, list)
            else ()
        )
        raw_owner = payload.get("cleanup_ownership")
        if not isinstance(raw_owner, dict):
            raise ValueError("side-scan cleanup ownership is required")
        provider = str(payload.get("provider") or "")
        if provider not in {"aws", "azure", "gcp"}:
            raise ValueError("unsupported side-scan provider")
        raw_warnings = payload.get("warning_codes")
        return cls(
            execution_id=str(payload.get("execution_id") or ""),
            idempotency_key=str(payload.get("idempotency_key") or ""),
            tenant_id=str(payload.get("tenant_id") or ""),
            provider=cast(SideScanProvider, provider),
            account_id=str(payload.get("account_id") or ""),
            target_id=str(payload.get("target_id") or ""),
            collector_id=str(payload.get("collector_id") or ""),
            cleanup_ownership=SideScanCleanupOwnership.from_dict(raw_owner),
            status=ExecutionStatus(str(payload.get("status") or "")),
            phase=str(payload.get("phase") or ""),
            cleanup_status=CleanupStatus(str(payload.get("cleanup_status") or "")),
            resources=resources,
            package_count=int(counts.get("package_count", 0)),
            vulnerability_count=int(counts.get("vulnerability_count", 0)),
            secret_count=int(counts.get("secret_count", 0)),
            config_finding_count=int(counts.get("config_finding_count", 0)),
            ioc_finding_count=int(counts.get("ioc_finding_count", 0)),
            failure_code=str(payload.get("failure_code") or ""),
            warning_codes=tuple(str(item) for item in raw_warnings) if isinstance(raw_warnings, list) else (),
            request_fingerprint=str(payload.get("request_fingerprint") or ""),
            state_version=_coerce_int(payload.get("state_version")),
            created_at=str(payload.get("created_at") or ""),
            updated_at=str(payload.get("updated_at") or ""),
        )


class SideScanStateConflictError(RuntimeError):
    """Raised when a stale worker attempts to overwrite newer lifecycle state."""


def _record_json(record: SideScanExecutionRecord) -> str:
    return json.dumps(record.to_dict(), sort_keys=True, separators=(",", ":"))


def _record_from_json(raw: str) -> SideScanExecutionRecord:
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("invalid persisted side-scan state")
    return SideScanExecutionRecord.from_dict(payload)


def _coerce_int(value: object) -> int:
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
