"""Tests for report artifact S3 publishing (#3512)."""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from agent_bom.api.report_artifact_store import (
    PublishedReportArtifact,
    publish_report_artifact,
    report_artifact_backend,
    s3_object_key,
)


def test_report_artifact_backend_defaults_local(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_REPORT_S3_BUCKET", raising=False)
    assert report_artifact_backend() == "local"


def test_report_artifact_backend_selects_s3_when_bucket_set(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_BUCKET", "customer-reports")
    assert report_artifact_backend() == "s3"


def test_s3_object_key_includes_prefix_and_tenant(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_PREFIX", "exports")
    key = s3_object_key("tenant/a", "job-123")
    assert key == "exports/tenant_a/job-123.ndjson.gz"


def test_publish_local_artifact(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_REPORT_S3_BUCKET", raising=False)
    artifact = tmp_path / "job.ndjson.gz"
    artifact.write_bytes(b"payload")

    published = publish_report_artifact(artifact, tenant_id="tenant-a", job_id="job-1")

    assert published == PublishedReportArtifact(
        backend="local",
        artifact_uri=str(artifact),
        presigned_download_url=None,
        local_path=artifact,
    )


def test_publish_s3_artifact_uploads_and_presigns(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_BUCKET", "customer-reports")
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_PREFIX", "report-artifacts")
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_REGION", "us-east-1")
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_PRESIGN_SECONDS", "7200")
    artifact = tmp_path / "job.ndjson.gz"
    artifact.write_bytes(b"payload")

    mock_client = MagicMock()
    mock_client.generate_presigned_url.return_value = "https://s3.example/presigned"
    fake_boto3 = MagicMock()
    fake_boto3.client.return_value = mock_client
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    published = publish_report_artifact(artifact, tenant_id="tenant-a", job_id="job-1")

    fake_boto3.client.assert_called_once_with("s3", region_name="us-east-1")
    mock_client.upload_file.assert_called_once()
    upload_args = mock_client.upload_file.call_args
    assert upload_args[0][0] == str(artifact)
    assert upload_args[0][1] == "customer-reports"
    assert upload_args[0][2] == "report-artifacts/tenant-a/job-1.ndjson.gz"
    mock_client.generate_presigned_url.assert_called_once_with(
        "get_object",
        Params={"Bucket": "customer-reports", "Key": "report-artifacts/tenant-a/job-1.ndjson.gz"},
        ExpiresIn=7200,
    )
    assert published.backend == "s3"
    assert published.artifact_uri == "s3://customer-reports/report-artifacts/tenant-a/job-1.ndjson.gz"
    assert published.presigned_download_url == "https://s3.example/presigned"


def test_publish_s3_requires_boto3(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_REPORT_S3_BUCKET", "customer-reports")
    artifact = tmp_path / "job.ndjson.gz"
    artifact.write_bytes(b"payload")
    monkeypatch.delitem(sys.modules, "boto3", raising=False)

    with pytest.raises(RuntimeError, match="boto3"):
        publish_report_artifact(artifact, tenant_id="tenant-a", job_id="job-1")
