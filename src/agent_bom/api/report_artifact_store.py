"""Report artifact storage backends: local filesystem and S3 (#3512)."""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

_logger = logging.getLogger(__name__)

ReportArtifactBackend = Literal["local", "s3"]


@dataclass(frozen=True)
class PublishedReportArtifact:
    backend: ReportArtifactBackend
    artifact_uri: str
    presigned_download_url: str | None
    local_path: Path | None


def _env_str(name: str, default: str = "") -> str:
    return (os.environ.get(name) or default).strip()


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not str(raw).strip():
        return default
    return int(raw)


def _safe_segment(value: str) -> str:
    return value.replace("/", "_").replace("\\", "_") or "default"


def report_artifact_backend() -> ReportArtifactBackend:
    if _env_str("AGENT_BOM_REPORT_S3_BUCKET"):
        return "s3"
    return "local"


def s3_object_key(tenant_id: str, job_id: str) -> str:
    prefix = _env_str("AGENT_BOM_REPORT_S3_PREFIX", "report-artifacts").strip("/")
    tenant = _safe_segment(tenant_id)
    name = f"{job_id}.ndjson.gz"
    return f"{prefix}/{tenant}/{name}" if prefix else f"{tenant}/{name}"


def publish_report_artifact(local_path: Path, *, tenant_id: str, job_id: str, attempt: str | None = None) -> PublishedReportArtifact:
    """Publish a completed gzip artifact to the configured backend."""
    backend = report_artifact_backend()
    if backend == "local":
        return PublishedReportArtifact(
            backend="local",
            artifact_uri=str(local_path),
            presigned_download_url=None,
            local_path=local_path,
        )
    return _publish_s3(local_path, tenant_id=tenant_id, job_id=job_id, attempt=attempt)


def _publish_s3(local_path: Path, *, tenant_id: str, job_id: str, attempt: str | None = None) -> PublishedReportArtifact:
    bucket = _env_str("AGENT_BOM_REPORT_S3_BUCKET")
    if not bucket:
        raise RuntimeError("AGENT_BOM_REPORT_S3_BUCKET is required for S3 report artifacts")

    try:
        import boto3
    except ImportError as exc:  # pragma: no cover - optional extra
        raise RuntimeError("S3 report artifacts require boto3; install with: pip install 'agent-bom[aws]'") from exc

    key = s3_object_key(tenant_id, f"{job_id}.{attempt}" if attempt else job_id)
    region = _env_str("AGENT_BOM_REPORT_S3_REGION")
    client_kwargs: dict[str, str] = {}
    if region:
        client_kwargs["region_name"] = region
    client = boto3.client("s3", **client_kwargs)
    client.upload_file(
        str(local_path),
        bucket,
        key,
        ExtraArgs={"ContentType": "application/gzip", "ServerSideEncryption": "AES256"},
    )
    presign_seconds = max(60, _env_int("AGENT_BOM_REPORT_S3_PRESIGN_SECONDS", 3_600))
    presigned = client.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket, "Key": key},
        ExpiresIn=presign_seconds,
    )
    uri = f"s3://{bucket}/{key}"
    _logger.info("Published report artifact for job %s to %s", job_id, uri)
    return PublishedReportArtifact(
        backend="s3",
        artifact_uri=uri,
        presigned_download_url=presigned,
        local_path=local_path,
    )


def presign_report_artifact(uri: str) -> str:
    """Mint a fresh short-lived URL only after tenant-authenticated job lookup."""
    from urllib.parse import urlsplit

    import boto3

    parsed = urlsplit(uri)
    bucket = _env_str("AGENT_BOM_REPORT_S3_BUCKET")
    if parsed.scheme != "s3" or not bucket or parsed.netloc != bucket or not parsed.path.lstrip("/"):
        raise RuntimeError("Stored report artifact does not match the configured bucket")
    region = _env_str("AGENT_BOM_REPORT_S3_REGION")
    client = boto3.client("s3", **({"region_name": region} if region else {}))
    return str(
        client.generate_presigned_url(
            "get_object",
            Params={"Bucket": bucket, "Key": parsed.path.lstrip("/")},
            ExpiresIn=max(60, _env_int("AGENT_BOM_REPORT_S3_PRESIGN_SECONDS", 3600)),
        )
    )


def validate_report_artifact_sharing() -> None:
    """Reject clustered local exports unless every replica shares artifact storage."""
    from agent_bom.api.durable_store import select_backend
    from agent_bom.api.middleware import clustered_control_plane_required

    if not clustered_control_plane_required():
        return
    if select_backend() != "postgres":
        raise RuntimeError("Clustered report exports require Postgres job storage")
    shared = _env_str("AGENT_BOM_REPORT_ARTIFACT_SHARED").lower() in {"1", "true", "yes", "on"}
    if report_artifact_backend() == "local" and not (shared and _env_str("AGENT_BOM_REPORT_ARTIFACT_DIR")):
        raise RuntimeError("Configure S3 artifacts or a shared report artifact directory before enabling clustered exports")
