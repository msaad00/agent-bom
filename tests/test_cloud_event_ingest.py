"""Tests for event-driven AWS posture ingestion (CloudTrail/EventBridge → SQS)."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from agent_bom.api.connection_store import (
    CloudConnectionRecord,
    InMemoryConnectionStore,
)
from agent_bom.cloud import event_ingest
from agent_bom.cloud.event_ingest import (
    CloudChangeEvent,
    consume_aws_events,
    dispatch_change_event,
    parse_cloudtrail_event,
)

_ACCOUNT = "123456789012"


def _record(*, account: str = _ACCOUNT) -> CloudConnectionRecord:
    return CloudConnectionRecord(
        id="conn-1",
        tenant_id="tenant-a",
        provider="aws",
        display_name="prod",
        role_ref=f"arn:aws:iam::{account}:role/agent-bom-readonly",
        external_id_encrypted="cipher",
        regions=["us-east-1"],
    )


def _s3_put_bucket_policy_event(*, account: str = _ACCOUNT, bucket: str = "public-bucket") -> dict[str, Any]:
    """A synthetic EventBridge-wrapped CloudTrail S3 PutBucketPolicy event."""
    return {
        "version": "0",
        "id": "evt-1",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.s3",
        "account": account,
        "region": "us-east-1",
        "detail": {
            "eventSource": "s3.amazonaws.com",
            "eventName": "PutBucketPolicy",
            "awsRegion": "us-east-1",
            "recipientAccountId": account,
            "userIdentity": {"accountId": account},
            "requestParameters": {"bucketName": bucket},
        },
    }


# --------------------------------------------------------------------------- #
# Fake read-only AWS session (drives both inventory + CIS)
# --------------------------------------------------------------------------- #


class _NoSuchPABError(Exception):
    """Stand-in for S3 NoSuchPublicAccessBlock (inventory reads it best-effort)."""


class _FakeS3:
    def list_buckets(self, **kwargs: Any) -> dict[str, Any]:
        return {"Buckets": [{"Name": "public-bucket", "CreationDate": None}]}

    def get_bucket_policy_status(self, **kwargs: Any) -> dict[str, Any]:
        return {"PolicyStatus": {"IsPublic": True}}  # made public

    def get_public_access_block(self, **kwargs: Any) -> dict[str, Any]:
        raise _NoSuchPABError("NoSuchPublicAccessBlock")

    def get_bucket_location(self, **kwargs: Any) -> dict[str, Any]:
        return {"LocationConstraint": "us-east-1"}

    def get_bucket_tagging(self, **kwargs: Any) -> dict[str, Any]:
        raise Exception("NoSuchTagSet")

    def get_bucket_encryption(self, **kwargs: Any) -> dict[str, Any]:
        return {}  # present → 2.1.2 passes

    def get_bucket_versioning(self, **kwargs: Any) -> dict[str, Any]:
        return {"Status": "Enabled", "MFADelete": "Enabled"}  # 2.1.3/2.1.4 pass

    def get_bucket_logging(self, **kwargs: Any) -> dict[str, Any]:
        return {"LoggingEnabled": True}


class _FakeS3Control:
    def get_public_access_block(self, **kwargs: Any) -> dict[str, Any]:
        # Account-level PAB not enforcing → CIS 2.1.1 FAILS (public not blocked).
        return {"PublicAccessBlockConfiguration": {}}


class _FakeCloudTrail:
    def describe_trails(self, **kwargs: Any) -> dict[str, Any]:
        return {"trailList": []}


class _FakeSTS:
    def get_caller_identity(self) -> dict[str, Any]:
        return {"Account": _ACCOUNT}


class _FakeSession:
    region_name = "us-east-1"

    def client(self, service: str, **kwargs: Any) -> Any:
        if service == "s3":
            return _FakeS3()
        if service == "s3control":
            return _FakeS3Control()
        if service == "cloudtrail":
            return _FakeCloudTrail()
        if service == "sts":
            return _FakeSTS()
        return MagicMock()  # unused services (their checks are filtered out)


class _FakeCISReport:
    def to_dict(self) -> dict[str, Any]:
        return {
            "benchmark": "CIS AWS Foundations",
            "benchmark_version": "3.0",
            "account_id": _ACCOUNT,
            "region": "us-east-1",
            "passed": 5,
            "failed": 1,
            "total": 6,
            "checks": [
                {
                    "check_id": "2.1.1",
                    "title": "Ensure that S3 Block Public Access is enabled account-wide",
                    "status": "fail",
                    "severity": "high",
                    "resource_ids": ["public-bucket"],
                    "evidence": "Account-level public access block is not fully enforced.",
                },
                {
                    "check_id": "2.1.2",
                    "title": "Ensure S3 buckets use server-side encryption",
                    "status": "pass",
                    "severity": "medium",
                    "resource_ids": ["public-bucket"],
                    "evidence": "Bucket encryption is configured.",
                },
                {
                    "check_id": "2.1.3",
                    "title": "Ensure S3 bucket versioning is enabled",
                    "status": "pass",
                    "severity": "medium",
                    "resource_ids": ["public-bucket"],
                    "evidence": "Versioning is enabled.",
                },
                {
                    "check_id": "2.1.4",
                    "title": "Ensure MFA delete is enabled",
                    "status": "pass",
                    "severity": "medium",
                    "resource_ids": ["public-bucket"],
                    "evidence": "MFA delete is enabled.",
                },
                {
                    "check_id": "3.3",
                    "title": "Ensure S3 bucket logging is enabled for CloudTrail buckets",
                    "status": "pass",
                    "severity": "medium",
                    "resource_ids": ["public-bucket"],
                    "evidence": "Bucket logging is enabled.",
                },
                {
                    "check_id": "3.6",
                    "title": "Ensure CloudTrail S3 bucket is not publicly accessible",
                    "status": "pass",
                    "severity": "high",
                    "resource_ids": ["public-bucket"],
                    "evidence": "Bucket policy is not public for CloudTrail writes.",
                },
            ],
        }


def _fake_run_benchmark(*, checks: list[str], **kwargs: Any) -> _FakeCISReport:
    assert set(checks) == {"2.1.1", "2.1.2", "2.1.3", "2.1.4", "3.3", "3.6"}
    return _FakeCISReport()


# --------------------------------------------------------------------------- #
# dispatch: S3 PutBucketPolicy → affected CIS check re-evaluates + finding
# --------------------------------------------------------------------------- #


def test_dispatch_s3_public_bucket_reevaluates_and_produces_finding() -> None:
    event = parse_cloudtrail_event(_s3_put_bucket_policy_event())
    assert event is not None
    assert event.resource_type == "s3"
    assert event.resource_id == "public-bucket"
    assert event.action == "PutBucketPolicy"

    record = _record()
    store = InMemoryConnectionStore()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        persisted["tenant_id"] = tenant_id
        return "scan-xyz"

    delta = dispatch_change_event(
        event,
        record,
        session=_FakeSession(),
        benchmark_runner=_fake_run_benchmark,
        persist=_persist,
        store=store,
    )

    assert delta is not None
    assert delta["scan_id"] == "scan-xyz"
    assert delta["provider"] == "aws"
    # ONLY the S3-type checks were re-evaluated (not the whole benchmark).
    assert set(delta["checks_evaluated"]) == {"2.1.1", "2.1.2", "2.1.3", "2.1.4", "3.3", "3.6"}
    # The affected resource was resolved from the scoped inventory fetch.
    assert delta["resource"] is not None
    assert delta["resource"]["name"] == "public-bucket"
    assert delta["resource"]["publicly_accessible"] is True
    # A finding was produced — the account-level public-access-block check failed.
    finding_ids = {f["check_id"] for f in delta["findings"]}
    assert "2.1.1" in finding_ids
    # The posture report reached the persistence path like a scan does.
    report = persisted["report"]
    assert report.cis_benchmark_data["failed"] >= 1
    assert report.scan_sources == ["cloud_connection", "cloud:aws", "event:cloudtrail"]
    # last_event_at freshness signal was stamped (distinct from last_scan_at).
    fresh = store.get("tenant-a", "conn-1")
    assert fresh is not None
    assert fresh.last_event_at is not None
    assert fresh.last_scan_at is None


def test_dispatch_drops_foreign_account_event_without_scanning() -> None:
    """A change event for an account the connection does not own is fail-closed."""
    event = parse_cloudtrail_event(_s3_put_bucket_policy_event(account="999999999999"))
    assert event is not None
    record = _record(account=_ACCOUNT)  # different account than the event
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "scan-should-not-happen"

    # Passing a bare object() as the session: the read-only path must never be
    # reached for a foreign account, so this object is never exercised.
    delta = dispatch_change_event(event, record, session=object(), persist=_persist)
    assert delta is None
    assert "hit" not in called


def test_dispatch_drops_unknown_resource_type() -> None:
    event = CloudChangeEvent(
        provider="aws",
        account=_ACCOUNT,
        region="us-east-1",
        resource_type="dynamodb",  # no posture rule
        resource_id="my-table",
        action="UpdateTable",
    )
    assert dispatch_change_event(event, _record(), session=_FakeSession()) is None


# --------------------------------------------------------------------------- #
# malformed-event guard
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "message",
    [
        "not json at all {",
        "[]",
        "null",
        json.dumps({"detail-type": "Some Other Event", "source": "aws.s3", "account": _ACCOUNT, "detail": {}}),
        # no resource id:
        json.dumps({"source": "aws.s3", "account": _ACCOUNT, "detail": {"eventName": "PutBucketPolicy"}}),
        # no account:
        json.dumps({"source": "aws.s3", "detail": {"eventName": "Put", "requestParameters": {"bucketName": "b"}}}),
        # unsupported service token:
        json.dumps({"source": "aws.dynamodb", "account": _ACCOUNT, "detail": {"eventName": "X", "requestParameters": {"k": "v"}}}),
    ],
)
def test_parse_malformed_event_returns_none(message: str) -> None:
    assert parse_cloudtrail_event(message) is None


# --------------------------------------------------------------------------- #
# consumer: bounded SQS drain
# --------------------------------------------------------------------------- #


class _FakeSQS:
    """Minimal SQS stub: hands back a fixed message list each receive."""

    def __init__(self, batches: list[list[dict[str, Any]]]) -> None:
        self._batches = batches
        self.receive_calls = 0
        self.deleted: list[str] = []

    def receive_message(self, **kwargs: Any) -> dict[str, Any]:
        self.receive_calls += 1
        if self._batches:
            return {"Messages": self._batches.pop(0)}
        return {}

    def delete_message(self, **kwargs: Any) -> None:
        self.deleted.append(kwargs["ReceiptHandle"])


def _msg(body: dict[str, Any], receipt: str) -> dict[str, Any]:
    return {"Body": json.dumps(body), "ReceiptHandle": receipt}


def test_consume_disabled_when_no_queue(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(event_ingest.EVENT_QUEUE_URL_ENV, raising=False)
    summary = consume_aws_events(_record())
    assert summary["status"] == "disabled"
    assert summary["received"] == 0


def test_consume_empty_queue_is_noop() -> None:
    sqs = _FakeSQS(batches=[])  # no messages ever
    summary = consume_aws_events(
        _record(),
        queue_url="https://sqs/queue",
        sqs_client=sqs,
        session=_FakeSession(),
    )
    assert summary["status"] == "ok"
    assert summary["received"] == 0
    assert summary["processed"] == 0
    assert sqs.receive_calls == 1  # one empty receive, then stop


def test_consume_bounded_batch_stops(monkeypatch: pytest.MonkeyPatch) -> None:
    """A never-empty queue is drained for at most max_batches receives, then returns."""
    # Every receive yields a full batch of malformed messages (kept unbounded).
    endless = _FakeSQS(batches=[])

    def _always_full(**kwargs: Any) -> dict[str, Any]:
        endless.receive_calls += 1
        return {"Messages": [_msg({"garbage": True}, f"r{endless.receive_calls}")]}

    monkeypatch.setattr(endless, "receive_message", _always_full)

    summary = consume_aws_events(
        _record(),
        queue_url="https://sqs/queue",
        sqs_client=endless,
        session=_FakeSession(),
        max_batches=3,
    )
    # Bounded: exactly max_batches receives, then it returned (no forever loop).
    assert endless.receive_calls == 3
    assert summary["batches"] == 3
    assert summary["skipped_malformed"] == 3
    assert summary["deleted"] == 3  # poison messages dropped


def test_consume_dispatches_and_deletes_valid_event() -> None:
    sqs = _FakeSQS(batches=[[_msg(_s3_put_bucket_policy_event(), "receipt-1")]])
    store = InMemoryConnectionStore()
    record = _record()
    store.put(record)
    persisted: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        persisted["report"] = report
        return "scan-1"

    summary = consume_aws_events(
        record,
        queue_url="https://sqs/queue",
        sqs_client=sqs,
        session=_FakeSession(),
        benchmark_runner=_fake_run_benchmark,
        persist=_persist,
        store=store,
        max_batches=2,
    )
    assert summary["processed"] == 1
    assert summary["deleted"] == 1
    assert sqs.deleted == ["receipt-1"]
    assert "report" in persisted


def test_consume_drops_foreign_account_message() -> None:
    foreign = _s3_put_bucket_policy_event(account="999999999999")
    sqs = _FakeSQS(batches=[[_msg(foreign, "receipt-foreign")]])
    called: dict[str, Any] = {}

    def _persist(rec: CloudConnectionRecord, tenant_id: str, report: Any) -> str:
        called["hit"] = True
        return "nope"

    summary = consume_aws_events(
        _record(account=_ACCOUNT),
        queue_url="https://sqs/queue",
        sqs_client=sqs,
        session=_FakeSession(),
        persist=_persist,
        max_batches=2,
    )
    assert summary["skipped_foreign"] == 1
    assert summary["processed"] == 0
    assert sqs.deleted == ["receipt-foreign"]  # dropped, not scanned
    assert "hit" not in called
