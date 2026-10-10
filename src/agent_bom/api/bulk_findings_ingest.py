"""Request models and row normalization for bulk finding ingest and package checks."""

from __future__ import annotations

import math
from typing import Any

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, field_validator

from agent_bom.canonical_ids import canonical_finding_id

_BULK_FINDINGS_MAX_ITEMS = 1000
_BULK_FINDINGS_SOURCE_MAX_LENGTH = 128


class BulkFindingsRequest(BaseModel):
    """Normalized finding ingest for headless clients and agent runtimes."""

    model_config = ConfigDict(extra="forbid")

    findings: list[dict[str, Any]] = Field(min_length=1, max_length=_BULK_FINDINGS_MAX_ITEMS)
    source: str = Field(default="api", min_length=1, max_length=_BULK_FINDINGS_SOURCE_MAX_LENGTH)
    schema_version: str = Field(default="v1", min_length=1, max_length=32)
    metadata: dict[str, Any] = Field(default_factory=dict)
    tenant_id: str | None = Field(default=None, description="Deprecated compatibility field; request tenant scope is authoritative.")
    observed_at: str | None = Field(
        default=None,
        description="Observation timestamp from scan completion; defaults to ingest time when omitted.",
    )
    reconcile_absent: bool = Field(
        default=False,
        description=("When true, mark open findings in the same source scope that are absent from this batch as resolved at observed_at."),
    )

    @field_validator("findings")
    @classmethod
    def _findings_must_be_objects(cls, value: list[dict[str, Any]]) -> list[dict[str, Any]]:
        for item in value:
            if not item:
                raise ValueError("findings must contain non-empty objects")
        return value

    @field_validator("source")
    @classmethod
    def _source_must_be_stable_label(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("source is required")
        return normalized


class PackageCheckRequest(BaseModel):
    """Pinned package check shared with the CLI and MCP surfaces."""

    model_config = ConfigDict(extra="forbid")

    package: str = Field(min_length=1, max_length=512)
    ecosystem: str = Field(default="npm", min_length=1, max_length=32)
    version: str | None = Field(default=None, max_length=256)
    offline: bool = False

    @field_validator("package")
    @classmethod
    def _package_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("package is required")
        return normalized

    @field_validator("ecosystem")
    @classmethod
    def _ecosystem_must_be_supported(cls, value: str) -> str:
        from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
        from agent_bom.mcp_server_runtime import validate_ecosystem

        return validate_ecosystem(value, SUPPORTED_PACKAGE_ECOSYSTEM_SET)


def _derive_bulk_finding_id(row: dict[str, Any], *, source: str) -> str:
    """Return a deterministic identity key for a bulk finding lacking an ``id``.

    Idempotency requires the identity key to be a pure function of finding
    content — never the per-attempt ``batch_id`` or wall clock. We fold in the
    stable discriminators (source, rule/vuln, location, package) via the shared
    ``uuid5`` canonicaliser so a resent identical batch collapses onto the same
    rows instead of appending duplicates.
    """
    raw_asset = row.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    rule = row.get("vulnerability_id") or row.get("cve_id") or row.get("rule_id") or row.get("title") or ""
    location = row.get("location") or row.get("file_path") or asset.get("location") or ""
    package = row.get("package") or row.get("package_name") or asset.get("name") or asset.get("identifier") or ""
    return canonical_finding_id(source, str(rule), str(location), str(package))


def _coerce_bulk_severity(value: Any, *, ordinal: int) -> str:
    """Validate/normalise a bulk finding's severity, failing closed on bad types.

    A non-string severity (nested object, number, list) cannot be honestly
    mapped to a severity bucket — accepting it materialised a row that leaked the
    value verbatim and never matched the severity filter. Reject it with a 422.
    A string severity is normalised to the canonical enum; an unrecognised label
    maps to ``unknown`` explicitly (never leaked as-is).
    """
    if value is None:
        return "unknown"
    if not isinstance(value, str):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: severity must be a string severity label, not {type(value).__name__}",
        )
    from agent_bom.core.severity import normalize_severity

    return normalize_severity(value)


def _coerce_bulk_cvss(value: Any, *, ordinal: int) -> float | None:
    """Validate/coerce a bulk finding's cvss_score to a 0.0-10.0 float or null.

    A non-numeric string (``"NaNstring"``), a nested object, NaN/inf, or an
    out-of-range number cannot be an honest CVSS base score — accepting it left a
    value that never matched a cvss filter. Reject it with a 422. ``None`` /
    absent is allowed (no score); a numeric string that parses cleanly in range
    is coerced to float.
    """
    if value is None:
        return None
    if isinstance(value, bool):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not bool",
        )
    if isinstance(value, (int, float)):
        score = float(value)
    elif isinstance(value, str):
        try:
            score = float(value)
        except ValueError:
            raise HTTPException(
                status_code=422,
                detail=f"finding {ordinal}: cvss_score {value!r} is not a number in 0.0-10.0",
            ) from None
    else:
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a number in 0.0-10.0 or null, not {type(value).__name__}",
        )
    if not math.isfinite(score) or not (0.0 <= score <= 10.0):
        raise HTTPException(
            status_code=422,
            detail=f"finding {ordinal}: cvss_score must be a finite number within 0.0-10.0",
        )
    return score


def _normalized_bulk_finding(row: dict[str, Any], *, source: str, batch_id: str, ordinal: int) -> dict[str, Any]:
    payload = dict(row)
    client_id = row.get("id")
    # Client-stable ids win; otherwise derive a content-deterministic id so
    # resends collapse (idempotent) rather than mint a fresh batch_id:ordinal.
    payload["id"] = str(client_id) if client_id else _derive_bulk_finding_id(row, source=source)
    payload.setdefault("source", source)
    # Fail closed on garbage severity/cvss types instead of materialising a row
    # that leaks the value verbatim and never matches the severity/cvss filter.
    payload["severity"] = _coerce_bulk_severity(row.get("severity"), ordinal=ordinal)
    cvss = _coerce_bulk_cvss(row.get("cvss_score"), ordinal=ordinal)
    if cvss is None:
        payload.pop("cvss_score", None)
    else:
        payload["cvss_score"] = cvss
    payload["origin"] = "bulk_ingest"
    payload["batch_id"] = batch_id
    payload["bulk_ordinal"] = ordinal
    return payload
