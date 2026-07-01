"""Tests for opt-in GCS content classification."""

from __future__ import annotations

from dataclasses import dataclass

from agent_bom.cloud import gcp_inventory
from agent_bom.cloud.gcs_data_classifier import classify_gcs_bucket, gcs_sampling_enabled


@dataclass
class _Blob:
    name: str
    size: int
    data: bytes

    def download_as_bytes(self, *, start: int = 0, end: int | None = None) -> bytes:
        end_idx = end + 1 if end is not None else None
        return self.data[start:end_idx]


class _Bucket:
    def __init__(self, name: str) -> None:
        self.name = name
        self.location = "US"
        self.labels = {"env": "prod"}

    def get_iam_policy(self) -> dict[str, list[dict[str, list[str]]]]:
        return {"bindings": []}


class _FakeStorageClient:
    def __init__(self, *, expected_max_results: int | None = None) -> None:
        self.expected_max_results = expected_max_results
        self.list_bucket_calls = 0
        self.list_blob_calls: list[tuple[str, int | None]] = []

    def list_buckets(self) -> list[_Bucket]:
        self.list_bucket_calls += 1
        return [_Bucket("prod-data")]

    def list_blobs(self, bucket: str, *, max_results: int | None = None) -> list[_Blob]:
        self.list_blob_calls.append((bucket, max_results))
        if self.expected_max_results is not None:
            assert max_results == self.expected_max_results
        return [
            _Blob("customers.csv", 128, b"email,ssn\nalice@example.com,123-45-6789\n"),
            _Blob("readme.txt", 8, b"hello"),
            _Blob("ignored.txt", 8, b"ignored"),
        ]


def test_gcs_sampling_flag_is_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_DSPM_GCS_SAMPLING", raising=False)

    assert gcs_sampling_enabled() is False


def test_gcs_classifier_is_bounded_and_redacted() -> None:
    client = _FakeStorageClient(expected_max_results=2)

    result = classify_gcs_bucket(client, "prod-data", max_objects=2, max_bytes_per_object=32)
    payload = result.to_dict()

    assert result.objects_sampled == 2
    assert result.total_findings >= 1
    assert payload["data_sensitivity"] == "sensitive"
    assert payload["redaction"] == "raw object bytes and matched values are not stored"
    assert client.list_blob_calls == [("prod-data", 2)]
    assert "alice@example.com" not in repr(payload)
    assert "123-45-6789" not in repr(payload)
    assert "[email:REDACTED]" in repr(payload)


def test_gcp_bucket_inventory_attaches_content_classification_when_enabled(monkeypatch) -> None:
    fake_client = _FakeStorageClient()
    monkeypatch.setenv("AGENT_BOM_DSPM_GCS_SAMPLING", "1")

    storage_module = type("_StorageModule", (), {"Client": staticmethod(lambda *_args, **_kwargs: fake_client)})

    real_import = __import__

    def _fake_import(name: str, globals=None, locals=None, fromlist=(), level: int = 0):  # noqa: ANN001
        if name == "google.cloud" and "storage" in fromlist:
            return type("_GoogleCloud", (), {"storage": storage_module})
        return real_import(name, globals, locals, fromlist, level)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    buckets = gcp_inventory._discover_buckets("project-1", credentials=None, warnings=[])

    assert buckets[0]["content_classification"]["data_sensitivity"] == "sensitive"
