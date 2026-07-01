"""Tests for opt-in S3 content classification."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from agent_bom.cloud import aws_inventory
from agent_bom.cloud.s3_data_classifier import classify_s3_bucket, s3_sampling_enabled


class _Body:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, _size: int = -1) -> bytes:
        return self._data


class _FakeS3:
    def __init__(self, *, expected_max_keys: int | None = None) -> None:
        self.expected_max_keys = expected_max_keys
        self.get_ranges: list[str] = []
        self.list_calls = 0

    def list_objects_v2(self, **kwargs: Any) -> dict[str, Any]:
        self.list_calls += 1
        if self.expected_max_keys is not None:
            assert kwargs["MaxKeys"] == self.expected_max_keys
        return {
            "Contents": [
                {"Key": "customers.csv", "Size": 128},
                {"Key": "readme.txt", "Size": 8},
                {"Key": "ignored.txt", "Size": 8},
            ]
        }

    def get_object(self, **kwargs: Any) -> dict[str, Any]:
        self.get_ranges.append(kwargs["Range"])
        if kwargs["Key"] == "customers.csv":
            return {"Body": _Body(b"email,ssn\nalice@example.com,123-45-6789\n")}
        return {"Body": _Body(b"hello")}


def test_s3_sampling_flag_is_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DSPM_S3_SAMPLING", raising=False)

    assert s3_sampling_enabled() is False


def test_s3_classifier_is_bounded_and_redacted() -> None:
    s3 = _FakeS3(expected_max_keys=2)

    result = classify_s3_bucket(s3, "prod-data", max_objects=2, max_bytes_per_object=32)
    payload = result.to_dict()

    assert result.objects_sampled == 2
    assert result.total_findings >= 1
    assert payload["data_sensitivity"] == "sensitive"
    assert payload["redaction"] == "raw object bytes and matched values are not stored"
    assert s3.get_ranges == ["bytes=0-31", "bytes=0-31"]
    assert "alice@example.com" not in repr(payload)
    assert "123-45-6789" not in repr(payload)
    assert "[email:REDACTED]" in repr(payload)


@dataclass
class _FakeSession:
    s3: _FakeS3

    def client(self, service: str, *_args: Any, **_kwargs: Any) -> Any:
        if service != "s3":
            raise AssertionError(service)
        return self.s3


def test_aws_bucket_inventory_attaches_content_classification_when_enabled(monkeypatch) -> None:
    fake_s3 = _FakeS3()
    monkeypatch.setenv("AGENT_BOM_DSPM_S3_SAMPLING", "1")
    monkeypatch.setattr(aws_inventory, "_bucket_location", lambda *_args, **_kwargs: "us-east-1")
    monkeypatch.setattr(aws_inventory, "_bucket_public", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(aws_inventory, "_bucket_tags", lambda *_args, **_kwargs: {})

    def _list_buckets() -> dict[str, Any]:
        return {"Buckets": [{"Name": "prod-data", "CreationDate": None}]}

    fake_s3.list_buckets = _list_buckets  # type: ignore[method-assign]

    buckets = aws_inventory._discover_s3_buckets(_FakeSession(fake_s3), account_id="123456789012", warnings=[])

    assert buckets[0]["content_classification"]["data_sensitivity"] == "sensitive"
