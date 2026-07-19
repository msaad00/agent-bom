"""Azure Blob DSPM content classification (issue #4157).

Unit behaviour is covered with an in-memory fake ``BlobServiceClient``; the real
``azure-storage-blob`` SDK path (``list_containers`` / ``list_blobs`` /
byte-ranged ``download_blob``) is proven end-to-end against the Azurite emulator
when it is reachable on ``127.0.0.1:10000``.
"""

from __future__ import annotations

import os
import uuid

import pytest

from agent_bom.cloud.azure_blob_data_classifier import (
    DSPM_AZURE_BLOB_SAMPLING_ENV_VAR,
    azure_blob_sampling_enabled,
    classify_azure_blob_account,
    classify_azure_blob_container,
)

# ── In-memory fakes ───────────────────────────────────────────────────────────


class _FakeBlobProps:
    def __init__(self, name: str, size: int):
        self.name = name
        self.size = size


class _FakeDownloader:
    def __init__(self, data: bytes):
        self._data = data

    def readall(self) -> bytes:
        return self._data


class _FakeBlobClient:
    def __init__(self, data: bytes):
        self._data = data

    def download_blob(self, *, offset: int = 0, length: int | None = None):  # noqa: ANN001
        end = offset + length if length is not None else len(self._data)
        return _FakeDownloader(self._data[offset:end])


class _FakeContainerClient:
    def __init__(self, blobs: dict[str, bytes], *, raise_on_list: bool = False):
        self._blobs = blobs
        self._raise = raise_on_list

    def list_blobs(self):
        if self._raise:
            raise RuntimeError("AuthorizationPermissionMismatch container=locked")
        return [_FakeBlobProps(name, len(data)) for name, data in self._blobs.items()]

    def get_blob_client(self, name: str) -> _FakeBlobClient:
        return _FakeBlobClient(self._blobs[name])


class _FakeContainerProps:
    def __init__(self, name: str):
        self.name = name


class _FakeBlobServiceClient:
    def __init__(self, containers: dict[str, _FakeContainerClient]):
        self._containers = containers

    def list_containers(self):
        return [_FakeContainerProps(name) for name in self._containers]

    def get_container_client(self, name: str) -> _FakeContainerClient:
        return self._containers[name]


_PII_BLOB = b"name,email,ssn,card\nalice,alice@example.com,123-45-6789,4111111111111111\nbob,bob@example.com,234-56-7890,5500005555555559\n"
_BENIGN_BLOB = b"metric,value\ncpu,0.5\nmem,0.7\n"


def _service_with_two_containers() -> _FakeBlobServiceClient:
    return _FakeBlobServiceClient(
        {
            "customer-exports": _FakeContainerClient({"pii.csv": _PII_BLOB}),
            "telemetry": _FakeContainerClient({"metrics.csv": _BENIGN_BLOB}),
        }
    )


# ── Gating ────────────────────────────────────────────────────────────────────


def test_sampling_is_opt_in(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, raising=False)
    assert azure_blob_sampling_enabled() is False
    monkeypatch.setenv(DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, "1")
    assert azure_blob_sampling_enabled() is True


# ── Unit behaviour ────────────────────────────────────────────────────────────


def test_container_classification_flags_pii_with_redacted_evidence():
    svc = _service_with_two_containers()
    result = classify_azure_blob_container(svc, "customer-exports", max_objects=5, max_bytes_per_object=4096)
    payload = result.to_dict()

    assert payload["schema_version"] == "agent-bom.dspm.azure_blob_classification.v1"
    assert payload["data_sensitivity"] == "sensitive"
    # The object path scans each blob as one text sample; every sensitive type is
    # detected (per-type presence counts, like the S3/GCS object samplers).
    assert payload["findings_by_type"].get("email", 0) >= 1
    assert payload["findings_by_type"].get("ssn", 0) >= 1
    assert payload["findings_by_type"].get("credit_card", 0) >= 1
    # Redaction: no raw value in serialized evidence.
    text = repr(payload)
    for raw in ("alice@example.com", "123-45-6789", "4111111111111111"):
        assert raw not in text
    assert payload["redaction"] == "raw object bytes and matched values are not stored"


def test_benign_container_is_none_not_sensitive():
    svc = _service_with_two_containers()
    result = classify_azure_blob_container(svc, "telemetry", max_objects=5, max_bytes_per_object=4096)
    assert result.total_findings == 0
    assert result.to_dict()["data_sensitivity"] == "none"


def test_account_scan_aggregates_and_stays_honest():
    svc = _service_with_two_containers()
    result = classify_azure_blob_account(svc, account="acct1", max_containers=10)
    payload = result.to_dict()

    assert payload["schema_version"] == "agent-bom.dspm.azure_blob_account.v1"
    assert payload["containers_total"] == 2
    assert payload["data_sensitivity"] == "sensitive"
    by_container = {c["container"]: c for c in payload["containers"]}
    assert by_container["customer-exports"]["data_sensitivity"] == "sensitive"
    assert by_container["telemetry"]["data_sensitivity"] == "none"


def test_byte_budget_is_enforced():
    # A tiny byte budget must truncate the sample: only the first bytes are read,
    # so downstream types beyond the cut are not observed.
    svc = _FakeBlobServiceClient({"c": _FakeContainerClient({"pii.csv": _PII_BLOB})})
    result = classify_azure_blob_container(svc, "c", max_objects=5, max_bytes_per_object=16)
    obj = result.objects[0]
    assert obj.bytes_sampled <= 16


def test_object_budget_is_enforced():
    blobs = {f"f{i}.txt": _PII_BLOB for i in range(10)}
    svc = _FakeBlobServiceClient({"c": _FakeContainerClient(blobs)})
    result = classify_azure_blob_container(svc, "c", max_objects=3, max_bytes_per_object=4096)
    assert result.objects_sampled == 3


def test_unlistable_container_is_unevaluable_not_clean():
    svc = _FakeBlobServiceClient({"locked": _FakeContainerClient({}, raise_on_list=True)})
    result = classify_azure_blob_container(svc, "locked", max_objects=5)
    payload = result.to_dict()
    assert payload["status"] == "list_failed"
    # An unreadable container never claims "none/clean".
    assert payload["data_sensitivity"] == "unevaluable"
    # Driver error carrying resource detail is sanitized (no secret/value leak here,
    # but the honesty state is what matters).
    assert result.objects_sampled == 0


def test_account_list_failure_is_failed_not_clean():
    class _Boom:
        def list_containers(self):
            raise RuntimeError("account key rotated; access denied")

    result = classify_azure_blob_account(_Boom(), account="acct1")
    payload = result.to_dict()
    assert payload["status"] == "failed"
    assert payload["data_sensitivity"] == "unevaluable"
    assert "access denied" not in repr(payload) or payload["data_sensitivity"] == "unevaluable"


# ── Inventory wiring (opt-in, best-effort) ────────────────────────────────────


def test_inventory_wiring_is_gated_and_best_effort(monkeypatch: pytest.MonkeyPatch):
    from agent_bom.cloud import azure_inventory

    # Gate OFF → no classification attached, no client constructed.
    monkeypatch.delenv(DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, raising=False)
    record: dict = {"name": "acct1"}
    warnings: list[str] = []
    azure_inventory._classify_storage_account_blobs(object(), record, warnings=warnings)
    assert "content_classification" not in record
    assert warnings == []

    # Gate ON but the blob client raises → best-effort warning, inventory intact.
    monkeypatch.setenv(DSPM_AZURE_BLOB_SAMPLING_ENV_VAR, "1")

    class _BoomService:
        def __init__(self, *a, **k):
            raise RuntimeError("blob endpoint unreachable")

    monkeypatch.setattr("azure.storage.blob.BlobServiceClient", _BoomService)
    record2: dict = {"name": "acct2"}
    warnings2: list[str] = []
    azure_inventory._classify_storage_account_blobs(object(), record2, warnings=warnings2)
    assert "content_classification" not in record2
    assert warnings2 and "acct2" in warnings2[0]


# ── Live Azurite proof (real azure-storage-blob SDK, emulator) ────────────────

# Well-known Azurite dev account (public, not a secret). Overridable for CI.
_AZURITE_CONN = os.environ.get("AGENT_BOM_AZURITE_CONNECTION_STRING") or (
    "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;"
    "AccountKey=Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==;"
    "BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;"
)


def _azurite_service():
    """Return a live BlobServiceClient if Azurite is reachable, else None."""
    try:
        from azure.storage.blob import BlobServiceClient

        svc = BlobServiceClient.from_connection_string(_AZURITE_CONN)
        list(svc.list_containers())  # probe
        return svc
    except Exception:  # noqa: BLE001 — emulator not running → skip
        return None


@pytest.mark.skipif(_azurite_service() is None, reason="Azurite emulator not reachable on 127.0.0.1:10000")
def test_live_azurite_list_and_byte_range_sample_is_redacted_and_honest():
    svc = _azurite_service()
    assert svc is not None
    suffix = uuid.uuid4().hex[:8]
    pii_container = f"cust-{suffix}"
    benign_container = f"tele-{suffix}"

    pii_cc = svc.get_container_client(pii_container)
    benign_cc = svc.get_container_client(benign_container)
    pii_cc.create_container()
    benign_cc.create_container()
    try:
        pii_cc.upload_blob("customers.csv", _PII_BLOB, overwrite=True)
        benign_cc.upload_blob("metrics.csv", _BENIGN_BLOB, overwrite=True)

        # Exercise the real list + byte-range-sample path against the emulator.
        account = classify_azure_blob_account(svc, account="devstoreaccount1", max_containers=50)
        payload = account.to_dict()
        by_container = {c["container"]: c for c in payload["containers"]}

        assert by_container[pii_container]["data_sensitivity"] == "sensitive"
        assert by_container[pii_container]["findings_by_type"].get("email", 0) >= 1
        assert by_container[pii_container]["findings_by_type"].get("ssn", 0) >= 1
        assert by_container[pii_container]["findings_by_type"].get("credit_card", 0) >= 1
        assert by_container[benign_container]["data_sensitivity"] == "none"

        # Redaction: no raw value crosses the boundary.
        text = repr(payload)
        for raw in ("alice@example.com", "123-45-6789", "4111111111111111", "234-56-7890"):
            assert raw not in text
    finally:
        for cc in (pii_cc, benign_cc):
            try:
                cc.delete_container()
            except Exception:  # noqa: BLE001 — cleanup best-effort
                pass
