"""Side-scan provider, status enums, transition tables and provider capabilities."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Literal

SideScanProvider = Literal["aws", "azure", "gcp"]

LIFECYCLE_SCHEMA_VERSION = "agent-bom.cwpp.side_scan.lifecycle.v1"
EVIDENCE_SCHEMA_VERSION = "agent-bom.cwpp.side_scan.evidence.v1"

_EXECUTION_NAMESPACE = uuid.UUID("91c9da65-16da-4e4c-9a4c-82f07918db88")
_PHASES = frozenset({"requested", "snapshot", "temp_disk", "attached", "mounted", "scanning", "cleanup", "finished"})


class ExecutionStatus(str, Enum):
    """Explicit side-scan execution outcomes; none imply a clean workload."""

    QUEUED = "queued"
    RUNNING = "running"
    SCAN_COMPLETE = "scan_complete"
    PARTIAL = "partial"
    DISABLED = "disabled"
    DENIED = "denied"
    FAILED = "failed"


class CleanupStatus(str, Enum):
    """Retryable teardown state for resources owned by one execution."""

    NOT_STARTED = "not_started"
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETE = "complete"
    PARTIAL = "partial"


class TemporaryResourceStatus(str, Enum):
    """Lifecycle state for a scanner-created cloud or collector resource."""

    CREATED = "created"
    CLEANUP_PENDING = "cleanup_pending"
    DELETED = "deleted"
    CLEANUP_FAILED = "cleanup_failed"


_EXECUTION_TRANSITIONS: dict[ExecutionStatus, frozenset[ExecutionStatus]] = {
    ExecutionStatus.QUEUED: frozenset(
        {
            ExecutionStatus.QUEUED,
            ExecutionStatus.RUNNING,
            ExecutionStatus.DISABLED,
            ExecutionStatus.DENIED,
            ExecutionStatus.FAILED,
        }
    ),
    ExecutionStatus.RUNNING: frozenset(
        {
            ExecutionStatus.RUNNING,
            ExecutionStatus.SCAN_COMPLETE,
            ExecutionStatus.PARTIAL,
            ExecutionStatus.DENIED,
            ExecutionStatus.FAILED,
        }
    ),
    ExecutionStatus.SCAN_COMPLETE: frozenset({ExecutionStatus.SCAN_COMPLETE, ExecutionStatus.PARTIAL}),
    ExecutionStatus.PARTIAL: frozenset({ExecutionStatus.PARTIAL}),
    ExecutionStatus.DISABLED: frozenset({ExecutionStatus.DISABLED}),
    ExecutionStatus.DENIED: frozenset({ExecutionStatus.DENIED}),
    ExecutionStatus.FAILED: frozenset({ExecutionStatus.FAILED}),
}

_CLEANUP_TRANSITIONS: dict[CleanupStatus, frozenset[CleanupStatus]] = {
    CleanupStatus.NOT_STARTED: frozenset(
        {CleanupStatus.NOT_STARTED, CleanupStatus.PENDING, CleanupStatus.IN_PROGRESS, CleanupStatus.COMPLETE}
    ),
    CleanupStatus.PENDING: frozenset({CleanupStatus.PENDING, CleanupStatus.IN_PROGRESS, CleanupStatus.COMPLETE, CleanupStatus.PARTIAL}),
    CleanupStatus.IN_PROGRESS: frozenset({CleanupStatus.IN_PROGRESS, CleanupStatus.COMPLETE, CleanupStatus.PARTIAL}),
    CleanupStatus.PARTIAL: frozenset({CleanupStatus.PARTIAL, CleanupStatus.IN_PROGRESS, CleanupStatus.COMPLETE}),
    CleanupStatus.COMPLETE: frozenset({CleanupStatus.COMPLETE}),
}

_RESOURCE_TRANSITIONS: dict[TemporaryResourceStatus, frozenset[TemporaryResourceStatus]] = {
    TemporaryResourceStatus.CREATED: frozenset(
        {
            TemporaryResourceStatus.CREATED,
            TemporaryResourceStatus.CLEANUP_PENDING,
            TemporaryResourceStatus.DELETED,
            TemporaryResourceStatus.CLEANUP_FAILED,
        }
    ),
    TemporaryResourceStatus.CLEANUP_PENDING: frozenset(
        {
            TemporaryResourceStatus.CLEANUP_PENDING,
            TemporaryResourceStatus.DELETED,
            TemporaryResourceStatus.CLEANUP_FAILED,
        }
    ),
    TemporaryResourceStatus.CLEANUP_FAILED: frozenset(
        {
            TemporaryResourceStatus.CLEANUP_FAILED,
            TemporaryResourceStatus.CLEANUP_PENDING,
            TemporaryResourceStatus.DELETED,
        }
    ),
    TemporaryResourceStatus.DELETED: frozenset({TemporaryResourceStatus.DELETED}),
}


@dataclass(frozen=True)
class SideScanProviderCapability:
    """Code-backed capability statement for one provider."""

    provider: SideScanProvider
    target_discovery: bool
    lifecycle_contract: bool
    executor: Literal["shipped", "contract_only"]
    cli_available: bool
    credentialed_smoke: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "provider": self.provider,
            "target_discovery": self.target_discovery,
            "lifecycle_contract": self.lifecycle_contract,
            "executor": self.executor,
            "cli_available": self.cli_available,
            "credentialed_smoke": self.credentialed_smoke,
        }


def side_scan_provider_capabilities() -> dict[SideScanProvider, SideScanProviderCapability]:
    """Return the shipped side-scan surface with an honest live-proof boundary.

    AWS EBS, Azure Managed Disk, and GCP Persistent Disk each ship a CLI
    executor over injected-SDK lifecycle adapters with durable ownership and
    guaranteed cleanup. ``credentialed_smoke`` stays ``False`` for every
    provider: no live-cloud smoke is claimed until it has actually run against
    read-only provider credentials. The flag advertises real proof, not intent.
    """
    return {
        "aws": SideScanProviderCapability("aws", True, True, "shipped", True, False),
        "azure": SideScanProviderCapability("azure", True, True, "shipped", True, False),
        "gcp": SideScanProviderCapability("gcp", True, True, "shipped", True, False),
    }
