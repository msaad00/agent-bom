"""Opt-in S3 content classification for DSPM evidence.

The default AWS inventory path is metadata-only. This module is deliberately
separate and gated by ``AGENT_BOM_DSPM_S3_SAMPLING`` because it reads bounded
object byte ranges. It never stores object bytes or matched values; the output
contains only counts, redacted finding markers, object keys, and warnings.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from agent_bom import config
from agent_bom.cloud.normalization import sanitize_discovery_warning
from agent_bom.parsers.dataset_pii_scanner import DatasetPiiResult, scan_text_for_pii

DSPM_S3_SAMPLING_ENV_VAR = "AGENT_BOM_DSPM_S3_SAMPLING"


def s3_sampling_enabled() -> bool:
    """Return whether bounded S3 content sampling is explicitly enabled."""
    return os.environ.get(DSPM_S3_SAMPLING_ENV_VAR, "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass
class S3ObjectClassification:
    bucket: str
    key: str
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
        bucket: str,
        key: str,
        size: int | None,
        bytes_sampled: int,
        result: DatasetPiiResult,
    ) -> "S3ObjectClassification":
        return cls(
            bucket=bucket,
            key=key,
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
            "bucket": self.bucket,
            "key": self.key,
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
class S3BucketClassification:
    bucket: str
    status: str
    objects_sampled: int = 0
    total_findings: int = 0
    findings_by_type: dict[str, int] = field(default_factory=dict)
    objects: list[S3ObjectClassification] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def sensitivity_score(self) -> int:
        if not self.total_findings:
            return 0
        high = sum(self.findings_by_type.get(kind, 0) for kind in {"ssn", "credit_card", "iban", "passport", "nhs_number"})
        if high:
            return 90
        if any(kind in self.findings_by_type for kind in {"email", "phone", "date_of_birth", "drivers_license", "medical_record_keyword"}):
            return 60
        return 30

    @property
    def data_sensitivity(self) -> str:
        if self.sensitivity_score >= 60:
            return "sensitive"
        if self.sensitivity_score > 0:
            return "review"
        return "none"

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "agent-bom.dspm.s3_classification.v1",
            "bucket": self.bucket,
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


def classify_s3_bucket(
    s3_client: Any,
    bucket: str,
    *,
    max_objects: int | None = None,
    max_bytes_per_object: int | None = None,
) -> S3BucketClassification:
    """Classify a bounded sample of S3 objects in *bucket*.

    Callers must check :func:`s3_sampling_enabled` before invoking this function
    from production scan paths. Tests may call it directly with fake clients.
    """
    max_objects = max(1, int(max_objects if max_objects is not None else config.DSPM_S3_MAX_OBJECTS_PER_BUCKET))
    max_bytes_per_object = max(1, int(max_bytes_per_object if max_bytes_per_object is not None else config.DSPM_S3_MAX_BYTES_PER_OBJECT))
    result = S3BucketClassification(bucket=bucket, status="ok")

    try:
        listed = s3_client.list_objects_v2(Bucket=bucket, MaxKeys=max_objects)
    except Exception as exc:  # noqa: BLE001
        result.status = "list_failed"
        result.warnings.append(f"Could not list S3 objects for {bucket}: {sanitize_discovery_warning(exc)}")
        return result

    for obj in (listed.get("Contents", []) or [])[:max_objects]:
        key = str(obj.get("Key") or "").strip()
        if not key:
            continue
        size = obj.get("Size")
        size_int = int(size) if isinstance(size, int) else None
        try:
            response = s3_client.get_object(Bucket=bucket, Key=key, Range=f"bytes=0-{max_bytes_per_object - 1}")
            body = response.get("Body")
            raw = body.read(max_bytes_per_object) if hasattr(body, "read") else b""
            if not isinstance(raw, (bytes, bytearray)):
                raw = str(raw).encode("utf-8", errors="replace")
            sample = bytes(raw[:max_bytes_per_object]).decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            result.warnings.append(f"Could not sample s3://{bucket}/{key}: {sanitize_discovery_warning(exc)}")
            continue

        pii_result = scan_text_for_pii(sample, source=f"s3://{bucket}/{key}", max_chars=max_bytes_per_object)
        classified = S3ObjectClassification.from_result(
            bucket=bucket,
            key=key,
            size=size_int,
            bytes_sampled=len(sample.encode("utf-8", errors="replace")),
            result=pii_result,
        )
        result.objects.append(classified)
        result.objects_sampled += 1
        result.total_findings += classified.total_findings
        for pii_type, count in classified.findings_by_type.items():
            result.findings_by_type[pii_type] = result.findings_by_type.get(pii_type, 0) + count

    return result
