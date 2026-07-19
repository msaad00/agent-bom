"""Opt-in Azure Blob content classification for DSPM evidence (issue #4157).

The default Azure inventory path is metadata-only (it reads storage-account
posture such as ``allow_blob_public_access`` and network rules — never blob
contents). This module is deliberately separate and gated by
``AGENT_BOM_DSPM_AZURE_BLOB_SAMPLING`` because it reads bounded blob byte ranges
through the real ``azure-storage-blob`` SDK (``BlobServiceClient`` →
``ContainerClient.list_blobs`` → ``BlobClient.download_blob(offset=, length=)``).

Honesty / safety constraints (parity with the S3 and GCS classifiers):

- **Redacted evidence only.** Raw blob bytes and matched values never cross the
  boundary — output is object name + counts + redacted finding types + warnings.
- **Bounded.** Container count, object count per container, and bytes per object
  are all capped; a byte-range GET reads only the sampled prefix.
- **Read-only.** Only ``list`` and byte-ranged ``download`` are issued; no blob,
  container, or account is mutated.
- **Fail honest.** A list/download failure is recorded as a warning and the
  container status reflects it — a container that could not be read is never
  reported clean.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from agent_bom import config
from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.parsers.dataset_pii_scanner import DatasetPiiResult, scan_text_for_pii

DSPM_AZURE_BLOB_SAMPLING_ENV_VAR = "AGENT_BOM_DSPM_AZURE_BLOB_SAMPLING"

_HIGH_SENSITIVITY_TYPES = frozenset({"ssn", "credit_card", "iban", "passport", "nhs_number"})
_MEDIUM_SENSITIVITY_TYPES = frozenset({"email", "phone", "date_of_birth", "drivers_license", "medical_record_keyword"})


def azure_blob_sampling_enabled() -> bool:
    """Return whether bounded Azure Blob content sampling is explicitly enabled."""
    return os.environ.get(DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


def _sensitivity(findings_by_type: dict[str, int]) -> tuple[int, str]:
    """Score/label redacted finding types — shared shape with the S3/GCS/DB classifiers."""
    if not findings_by_type:
        return 0, "none"
    if any(k in _HIGH_SENSITIVITY_TYPES or k.startswith("secret:") for k in findings_by_type):
        return 90, "sensitive"
    if any(k in _MEDIUM_SENSITIVITY_TYPES for k in findings_by_type):
        return 60, "sensitive"
    return 30, "review"


@dataclass
class AzureBlobObjectClassification:
    container: str
    name: str
    size: int | None
    bytes_sampled: int
    rows_sampled: int
    total_findings: int
    findings_by_type: dict[str, int] = field(default_factory=dict)
    top_findings: list[dict[str, Any]] = field(default_factory=list)
    skipped: bool = False
    skip_reason: str = ""

    @classmethod
    def from_result(
        cls,
        *,
        container: str,
        name: str,
        size: int | None,
        bytes_sampled: int,
        result: DatasetPiiResult,
    ) -> "AzureBlobObjectClassification":
        return cls(
            container=container,
            name=name,
            size=size,
            bytes_sampled=bytes_sampled,
            rows_sampled=result.rows_sampled,
            total_findings=result.total_findings,
            findings_by_type=dict(result.findings_by_type),
            top_findings=[
                {
                    "pii_type": finding.pii_type,
                    "severity": finding.severity,
                    "sample": finding.sample,
                }
                for finding in result.top_findings
            ],
            skipped=result.skipped,
            skip_reason=result.skip_reason,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "container": self.container,
            "name": self.name,
            "size": self.size,
            "bytes_sampled": self.bytes_sampled,
            "rows_sampled": self.rows_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "top_findings": list(self.top_findings),
            "skipped": self.skipped,
            "skip_reason": self.skip_reason,
        }


@dataclass
class AzureBlobContainerClassification:
    container: str
    status: str
    objects_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    objects: list[AzureBlobObjectClassification] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sensitivity_score(self) -> int:
        return _sensitivity(self.findings_by_type)[0]

    @property
    def data_sensitivity(self) -> str:
        # A container that could not be listed is unevaluable, never "clean".
        if self.status not in {"ok"} and not self.findings_by_type:
            return "unevaluable"
        return _sensitivity(self.findings_by_type)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-bom.dspm.azure_blob_classification.v1",
            "container": self.container,
            "status": self.status,
            "objects_sampled": self.objects_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "sensitivity_score": self.sensitivity_score,
            "data_sensitivity": self.data_sensitivity,
            "objects": [obj.to_dict() for obj in self.objects],
            "warnings": list(self.warnings),
            "redaction": "raw object bytes and matched values are not stored",
        }


@dataclass
class AzureBlobAccountClassification:
    """Redacted, coverage-honest DSPM classification for one storage account."""

    account: str
    status: str = "ok"
    containers_total: int = 0
    containers_sampled: int = 0
    objects_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    containers: list[AzureBlobContainerClassification] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sensitivity_score(self) -> int:
        return _sensitivity(self.findings_by_type)[0]

    @property
    def data_sensitivity(self) -> str:
        if not self.findings_by_type:
            evaluated = any(c.status == "ok" for c in self.containers)
            if self.status == "failed" or not evaluated:
                return "unevaluable"
        return _sensitivity(self.findings_by_type)[1]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-bom.dspm.azure_blob_account.v1",
            "account": self.account,
            "status": self.status,
            "containers_total": self.containers_total,
            "containers_sampled": self.containers_sampled,
            "objects_sampled": self.objects_sampled,
            "total_findings": self.total_findings,
            "findings_by_type": dict(self.findings_by_type),
            "sensitivity_score": self.sensitivity_score,
            "data_sensitivity": self.data_sensitivity,
            "containers": [c.to_dict() for c in self.containers],
            "warnings": list(self.warnings),
            "coverage_note": (
                "Container/object/byte budgets bound the sample; a container that could not be listed or read is unevaluable, not clean."
            ),
            "redaction": "raw object bytes and matched values are not stored",
        }


def classify_azure_blob_container(
    blob_service_client: Any,
    container: str,
    *,
    max_objects: int | None = None,
    max_bytes_per_object: int | None = None,
) -> AzureBlobContainerClassification:
    """Classify a bounded sample of blobs in *container* via byte-range downloads.

    Callers must check :func:`azure_blob_sampling_enabled` before invoking this
    from production scan paths. Tests may call it directly (e.g. against Azurite).
    """
    max_objects = max(1, int(max_objects if max_objects is not None else config.DSPM_AZURE_BLOB_MAX_OBJECTS_PER_CONTAINER))
    max_bytes_per_object = max(
        1, int(max_bytes_per_object if max_bytes_per_object is not None else config.DSPM_AZURE_BLOB_MAX_BYTES_PER_OBJECT)
    )
    result = AzureBlobContainerClassification(container=container, status="ok")

    try:
        container_client = blob_service_client.get_container_client(container)
        blob_iter = container_client.list_blobs()
    except Exception as exc:  # noqa: BLE001
        result.status = "list_failed"
        result.warnings.append(f"Could not list Azure Blob container {container}: {sanitize_discovery_warning(exc)}")
        return result

    sampled = 0
    for blob in blob_iter:
        if sampled >= max_objects:
            break
        name = str(getattr(blob, "name", "") or (blob.get("name") if isinstance(blob, dict) else "") or "").strip()
        if not name:
            continue
        raw_size = getattr(blob, "size", None)
        if raw_size is None and isinstance(blob, dict):
            raw_size = blob.get("size")
        size_int = int(raw_size) if isinstance(raw_size, int) else None
        try:
            blob_client = container_client.get_blob_client(name)
            downloader = blob_client.download_blob(offset=0, length=max_bytes_per_object)
            raw = downloader.readall()
            if not isinstance(raw, (bytes, bytearray)):
                raw = str(raw).encode("utf-8", errors="replace")
            sample = bytes(raw[:max_bytes_per_object]).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.warnings.append(f"Could not sample azure-blob://{container}/{name}: {sanitize_discovery_warning(exc)}")
            continue

        pii_result = scan_text_for_pii(sample, source=f"azure-blob://{container}/{name}", max_chars=max_bytes_per_object)
        classified = AzureBlobObjectClassification.from_result(
            container=container,
            name=name,
            size=size_int,
            bytes_sampled=len(sample.encode("utf-8", errors="replace")),
            result=pii_result,
        )
        result.objects.append(classified)
        result.objects_sampled += 1
        sampled += 1
        result.total_findings += classified.total_findings
        for pii_type, count in classified.findings_by_type.items():
            result.findings_by_type[pii_type] = result.findings_by_type.get(pii_type, 0) + count

    return result


def classify_azure_blob_account(
    blob_service_client: Any,
    *,
    account: str,
    max_containers: int | None = None,
    max_objects_per_container: int | None = None,
    max_bytes_per_object: int | None = None,
) -> AzureBlobAccountClassification:
    """Enumerate a storage account's containers and classify a bounded blob sample.

    Lists up to ``max_containers`` containers (read-only) and, for each, samples a
    bounded set of blobs. A container-listing failure marks the account ``failed``
    so an unreadable account is never reported clean.
    """
    max_containers = max(1, int(max_containers if max_containers is not None else config.DSPM_AZURE_BLOB_MAX_CONTAINERS))
    result = AzureBlobAccountClassification(account=account, status="ok")

    try:
        container_iter = blob_service_client.list_containers()
    except Exception as exc:  # noqa: BLE001
        result.status = "failed"
        result.warnings.append(f"Could not list containers for storage account {account}: {sanitize_discovery_warning(exc)}")
        return result

    names: list[str] = []
    for entry in container_iter:
        name = str(getattr(entry, "name", "") or (entry.get("name") if isinstance(entry, dict) else "") or "").strip()
        if not name:
            continue
        names.append(name)
        if len(names) >= max_containers:
            break
    result.containers_total = len(names)

    saw_gap = False
    for name in names:
        container_result = classify_azure_blob_container(
            blob_service_client,
            name,
            max_objects=max_objects_per_container,
            max_bytes_per_object=max_bytes_per_object,
        )
        result.containers.append(container_result)
        if container_result.status == "ok":
            result.containers_sampled += 1
            result.objects_sampled += container_result.objects_sampled
            result.total_findings += container_result.total_findings
            for pii_type, count in container_result.findings_by_type.items():
                result.findings_by_type[pii_type] = result.findings_by_type.get(pii_type, 0) + count
        else:
            saw_gap = True

    if saw_gap and result.status == "ok":
        result.status = "partial"
    return result
