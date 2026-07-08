"""Tests for read-only cloud audit-trail ingestion → behavioral graph edges.

Covers: opt-in gating, read-only readers (AWS/Azure/GCP) with mocked clients,
missing-permission → actionable message + no crash, cap-respected + warns,
aggregation/dedup + count, no-raw-log retention, determinism, and the
graph builder ``_add_cloud_audit_behavioral`` ACCESSED/INVOKED edge layer.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from agent_bom.cloud.audit_trail import (
    AuditEvent,
    aggregate_events,
    classify_action,
    collect_audit_trail,
    derive_behavioral_findings,
    is_enabled,
    lookback_hours,
    max_events,
    read_aws_cloudtrail,
    read_azure_activity_log,
    read_gcp_audit_logs,
)
from agent_bom.graph.builder import _add_cloud_audit_behavioral
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import RelationshipType

_NOW = datetime(2026, 6, 24, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _enable_audit(monkeypatch):
    """Opt-in is ON for most tests; the gating test overrides it."""
    monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL", "1")
    monkeypatch.delenv("AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_TRAIL_LOOKBACK_HOURS", raising=False)


# ── Opt-in gating ──────────────────────────────────────────────────────────


class TestOptIn:
    def test_disabled_by_default(self, monkeypatch):
        monkeypatch.delenv("AGENT_BOM_AUDIT_TRAIL", raising=False)
        assert is_enabled() is False

    def test_enabled_truthy_values(self, monkeypatch):
        for val in ("1", "true", "YES", "on"):
            monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL", val)
            assert is_enabled() is True

    def test_collect_skips_when_not_opted_in(self, monkeypatch):
        monkeypatch.delenv("AGENT_BOM_AUDIT_TRAIL", raising=False)
        payload = collect_audit_trail(provider="aws", now=_NOW)
        assert payload["status"] == "skipped"
        assert "AGENT_BOM_AUDIT_TRAIL" in payload["reason"]
        assert payload["behavioral_edges" if "behavioral_edges" in payload else "warnings"] is not None


# ── Bounds ─────────────────────────────────────────────────────────────────


class TestBounds:
    def test_defaults(self):
        assert lookback_hours() == 24
        assert max_events() == 2000

    def test_lookback_clamped(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL_LOOKBACK_HOURS", "999999")
        assert lookback_hours() == 24 * 14

    def test_max_events_clamped(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS", "999999999")
        assert max_events() == 20000

    def test_bad_int_falls_back(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS", "not-a-number")
        assert max_events() == 2000


# ── Action classification ──────────────────────────────────────────────────


class TestClassifyAction:
    @pytest.mark.parametrize(
        "action,expected",
        [
            ("ec2:RunInstances", "invoked"),
            ("CreateBucket", "invoked"),
            ("DeleteRole", "invoked"),
            ("Microsoft.Storage/storageAccounts/write", "invoked"),
            ("storage.objects.get", "accessed"),
            ("DescribeInstances", "accessed"),
            ("ListBuckets", "accessed"),
            ("", "accessed"),
            ("SomethingUnknown", "accessed"),
        ],
    )
    def test_classify(self, action, expected):
        assert classify_action(action) == expected


# ── Aggregation / dedup / count / determinism / no-raw-log ─────────────────


class TestAggregation:
    def _events(self):
        return [
            AuditEvent("alice", "GetObject", "bucket/data", "2026-06-24T10:00:00+00:00"),
            AuditEvent("alice", "GetObject", "bucket/data", "2026-06-24T11:00:00+00:00"),
            AuditEvent("alice", "GetObject", "bucket/data", "2026-06-24T09:00:00+00:00"),
            AuditEvent("bob", "CreateRole", "iam/admin", "2026-06-24T08:00:00+00:00"),
        ]

    def test_dedup_and_count(self):
        records = aggregate_events(self._events())
        assert len(records) == 2
        alice = next(r for r in records if r["principal"] == "alice")
        assert alice["count"] == 3
        assert alice["relationship"] == "accessed"

    def test_last_seen_is_latest(self):
        records = aggregate_events(self._events())
        alice = next(r for r in records if r["principal"] == "alice")
        assert alice["last_seen"] == "2026-06-24T11:00:00+00:00"

    def test_invoke_classification_in_aggregate(self):
        records = aggregate_events(self._events())
        bob = next(r for r in records if r["principal"] == "bob")
        assert bob["relationship"] == "invoked"

    def test_sensitive_resource_flag(self):
        records = aggregate_events(self._events())
        bob = next(r for r in records if r["principal"] == "bob")
        assert bob["is_sensitive_resource"] is True

    def test_deterministic_sorted_output(self):
        import random

        events = self._events()
        shuffled = list(events)
        random.shuffle(shuffled)
        assert aggregate_events(events) == aggregate_events(shuffled)

    def test_no_raw_logs_in_records(self):
        records = aggregate_events(self._events())
        for rec in records:
            assert set(rec.keys()) == {
                "principal",
                "action",
                "resource",
                "relationship",
                "count",
                "last_seen",
                "failure_count",
                "is_sensitive_resource",
            }

    def test_failure_count_tracked(self):
        events = [
            AuditEvent("eve", "AssumeRole", "iam/role", "2026-06-24T10:00:00+00:00", outcome="failure"),
            AuditEvent("eve", "AssumeRole", "iam/role", "2026-06-24T10:01:00+00:00", outcome="failure"),
            AuditEvent("eve", "AssumeRole", "iam/role", "2026-06-24T10:02:00+00:00", outcome="failure"),
        ]
        records = aggregate_events(events)
        assert records[0]["failure_count"] == 3


# ── Findings ────────────────────────────────────────────────────────────────


class TestFindings:
    def test_sensitive_access_finding(self):
        records = aggregate_events([AuditEvent("bob", "GetSecretValue", "secretsmanager/db-pass", "2026-06-24T10:00:00+00:00")])
        findings = derive_behavioral_findings(records)
        assert any(f["kind"] == "sensitive_resource_access" for f in findings)

    def test_repeated_failure_finding(self):
        records = aggregate_events(
            [AuditEvent("eve", "ListObjects", "bucket/x", f"2026-06-24T10:0{i}:00+00:00", outcome="failure") for i in range(4)]
        )
        findings = derive_behavioral_findings(records)
        assert any(f["kind"] == "repeated_access_failure" for f in findings)

    def test_clean_records_no_findings(self):
        records = aggregate_events([AuditEvent("alice", "ListBuckets", "s3", "2026-06-24T10:00:00+00:00")])
        assert derive_behavioral_findings(records) == []


# ── AWS CloudTrail reader (mocked) ─────────────────────────────────────────


class _FakeAWSPaginator:
    def __init__(self, pages):
        self._pages = pages

    def paginate(self, **kwargs):
        return self._pages


class _FakeAWSClient:
    def __init__(self, pages=None, error=None):
        self._pages = pages or []
        self._error = error

    def get_paginator(self, name):
        assert name == "lookup_events"
        if self._error:
            raise self._error
        return _FakeAWSPaginator(self._pages)


class _FakeAWSSession:
    def __init__(self, client):
        self._client = client

    def client(self, name):
        assert name == "cloudtrail"
        return self._client


class TestAWSReader:
    def test_reads_and_normalizes(self):
        pages = [
            {
                "Events": [
                    {
                        "EventName": "GetObject",
                        "Username": "alice",
                        "EventTime": datetime(2026, 6, 24, 10, 0, tzinfo=timezone.utc),
                        "Resources": [{"ResourceName": "bucket/data", "ResourceType": "AWS::S3::Object"}],
                        "EventSource": "s3.amazonaws.com",
                    }
                ]
            }
        ]
        events, warnings = read_aws_cloudtrail(now=_NOW, session_factory=lambda: _FakeAWSSession(_FakeAWSClient(pages)))
        assert warnings == []
        assert len(events) == 1
        assert events[0].principal == "alice"
        assert events[0].action == "GetObject"
        assert events[0].resource == "bucket/data"

    def test_access_denied_actionable(self):
        pytest.importorskip("botocore")  # ClientError is built here; botocore is in the [aws] extra, not the base test env
        from botocore.exceptions import ClientError

        denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "denied"}}, "LookupEvents")
        events, warnings = read_aws_cloudtrail(now=_NOW, session_factory=lambda: _FakeAWSSession(_FakeAWSClient(error=denied)))
        assert events == []
        assert len(warnings) == 1
        assert "cloudtrail:LookupEvents" in warnings[0]

    def test_cap_respected_and_warns(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_AUDIT_TRAIL_MAX_EVENTS", "2")
        pages = [
            {
                "Events": [
                    {
                        "EventName": f"Event{i}",
                        "Username": f"user{i}",
                        "EventTime": datetime(2026, 6, 24, 10, 0, tzinfo=timezone.utc),
                        "Resources": [{"ResourceName": f"res{i}"}],
                    }
                    for i in range(10)
                ]
            }
        ]
        events, warnings = read_aws_cloudtrail(now=_NOW, session_factory=lambda: _FakeAWSSession(_FakeAWSClient(pages)))
        assert len(events) == 2
        assert any("capped at 2" in w for w in warnings)


# ── Azure Activity Log reader (mocked) ─────────────────────────────────────


class _AzureRecord:
    def __init__(self, caller, op, resource, status="Succeeded"):
        self.caller = caller
        self.operation_name = type("Op", (), {"value": op})()
        self.resource_id = resource
        self.status = type("St", (), {"value": status})()
        self.event_timestamp = datetime(2026, 6, 24, 10, 0, tzinfo=timezone.utc)


class _FakeAzureActivityLogs:
    def __init__(self, records, error=None):
        self._records = records
        self._error = error

    def list(self, filter):  # noqa: A002 - matches SDK signature
        if self._error:
            raise self._error
        return iter(self._records)


class _FakeAzureClient:
    def __init__(self, records=None, error=None):
        self.activity_logs = _FakeAzureActivityLogs(records or [], error)


class TestAzureReader:
    def test_reads_and_normalizes(self):
        recs = [_AzureRecord("svc@x.com", "Microsoft.Storage/write", "/subs/abc/res/foo")]
        events, warnings = read_azure_activity_log(subscription_id="sub-1", now=_NOW, client_factory=lambda: _FakeAzureClient(recs))
        assert warnings == []
        assert events[0].principal == "svc@x.com"
        assert events[0].action == "Microsoft.Storage/write"
        assert events[0].resource == "/subs/abc/res/foo"

    def test_missing_subscription_actionable(self, monkeypatch):
        monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
        events, warnings = read_azure_activity_log(now=_NOW, client_factory=lambda: _FakeAzureClient([]))
        assert events == []
        assert any("AZURE_SUBSCRIPTION_ID" in w for w in warnings)

    def test_permission_denied_actionable(self):
        events, warnings = read_azure_activity_log(
            subscription_id="sub-1",
            now=_NOW,
            client_factory=lambda: _FakeAzureClient(error=Exception("AuthorizationFailed")),
        )
        assert events == []
        # Names the exact read and the existing Reader role it reuses (no new role).
        assert any("Microsoft.Insights/eventtypes/values/read" in w and "Reader" in w for w in warnings)


# ── GCP Cloud Audit Logs reader (mocked) ───────────────────────────────────


class _GCPEntry:
    def __init__(self, principal, method, resource, code=0):
        self.payload = {
            "authenticationInfo": {"principalEmail": principal},
            "methodName": method,
            "resourceName": resource,
            "status": {"code": code},
        }
        self.timestamp = datetime(2026, 6, 24, 10, 0, tzinfo=timezone.utc)


class _FakeGCPClient:
    def __init__(self, entries=None, error=None):
        self._entries = entries or []
        self._error = error

    def list_entries(self, filter_, page_size):
        if self._error:
            raise self._error
        return iter(self._entries)


class TestGCPReader:
    def test_reads_and_normalizes(self):
        entries = [_GCPEntry("sa@proj.iam", "storage.objects.get", "projects/_/buckets/b/objects/o")]
        events, warnings = read_gcp_audit_logs(project_id="proj", now=_NOW, client_factory=lambda: _FakeGCPClient(entries))
        assert warnings == []
        assert events[0].principal == "sa@proj.iam"
        assert events[0].action == "storage.objects.get"

    def test_missing_project_actionable(self, monkeypatch):
        monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
        events, warnings = read_gcp_audit_logs(now=_NOW, client_factory=lambda: _FakeGCPClient([]))
        assert events == []
        assert any("GOOGLE_CLOUD_PROJECT" in w for w in warnings)

    def test_permission_denied_actionable(self):
        events, warnings = read_gcp_audit_logs(
            project_id="proj",
            now=_NOW,
            client_factory=lambda: _FakeGCPClient(error=Exception("PermissionDenied: logging.logEntries.list")),
        )
        assert events == []
        # Names the exact read and the existing roles/viewer role it reuses (no new role).
        assert any("logging.logEntries.list" in w and "roles/viewer" in w for w in warnings)

    def test_failure_outcome_from_status_code(self):
        entries = [_GCPEntry("sa@proj.iam", "storage.buckets.delete", "buckets/b", code=7)]
        events, _ = read_gcp_audit_logs(project_id="proj", now=_NOW, client_factory=lambda: _FakeGCPClient(entries))
        assert events[0].outcome == "failure"


# ── collect_audit_trail end-to-end (no raw logs in payload) ────────────────


class TestCollect:
    def test_ok_payload_has_no_raw_events(self):
        pages = [
            {
                "Events": [
                    {
                        "EventName": "GetObject",
                        "Username": "alice",
                        "EventTime": datetime(2026, 6, 24, 10, 0, tzinfo=timezone.utc),
                        "Resources": [{"ResourceName": "bucket/data"}],
                    }
                ]
            }
        ]
        payload = collect_audit_trail(
            provider="aws",
            account="123456789012",
            now=_NOW,
            session_factory=lambda: _FakeAWSSession(_FakeAWSClient(pages)),
        )
        assert payload["status"] == "ok"
        assert payload["account"] == "123456789012"
        assert payload["event_count"] == 1
        assert "behavioral_edges" in payload
        # No raw event list, no log lines retained anywhere in the payload.
        assert "events" not in payload
        assert "raw_events" not in payload

    def test_unknown_provider_errors(self):
        payload = collect_audit_trail(provider="oracle", now=_NOW)
        assert payload["status"] == "error"


# ── Graph builder: ACCESSED / INVOKED behavioral edges ─────────────────────


def _payload(edges):
    return {
        "status": "ok",
        "provider": "aws",
        "account": "123456789012",
        "behavioral_edges": edges,
        "behavioral_findings": [],
        "event_count": len(edges),
        "warnings": [],
    }


class TestBuilderBehavioralEdges:
    def _build(self, edges):
        graph = UnifiedGraph()
        _add_cloud_audit_behavioral(graph, _payload(edges), "scan")
        return graph

    def test_accessed_edge_drawn(self):
        graph = self._build(
            [
                {
                    "principal": "alice",
                    "action": "GetObject",
                    "resource": "bucket/data",
                    "relationship": "accessed",
                    "count": 3,
                    "last_seen": "2026-06-24T11:00:00+00:00",
                    "failure_count": 0,
                    "is_sensitive_resource": False,
                }
            ]
        )
        edges = list(graph.edges)
        accessed = [e for e in edges if e.relationship == RelationshipType.ACCESSED]
        assert len(accessed) == 1
        assert accessed[0].evidence["observed"] is True
        assert accessed[0].evidence["observation_count"] == 3
        assert accessed[0].evidence["observed_at"] == "2026-06-24T11:00:00+00:00"

    def test_invoked_edge_drawn(self):
        graph = self._build(
            [
                {
                    "principal": "bob",
                    "action": "CreateRole",
                    "resource": "iam/admin",
                    "relationship": "invoked",
                    "count": 1,
                    "last_seen": "2026-06-24T08:00:00+00:00",
                    "failure_count": 0,
                    "is_sensitive_resource": True,
                }
            ]
        )
        invoked = [e for e in graph.edges if e.relationship == RelationshipType.INVOKED]
        assert len(invoked) == 1
        assert invoked[0].evidence["action"] == "CreateRole"

    def test_principal_and_resource_nodes_created(self):
        graph = self._build(
            [
                {
                    "principal": "alice",
                    "action": "GetObject",
                    "resource": "bucket/data",
                    "relationship": "accessed",
                    "count": 1,
                    "last_seen": "",
                    "failure_count": 0,
                    "is_sensitive_resource": False,
                }
            ]
        )
        node_ids = set(graph.nodes)
        assert any("user:aws:alice" in n for n in node_ids)
        assert any("cloud_resource:aws:audit:resource:bucket/data" in n for n in node_ids)

    def test_deterministic_same_payload_same_graph(self):
        edges = [
            {
                "principal": "alice",
                "action": "GetObject",
                "resource": "bucket/data",
                "relationship": "accessed",
                "count": 2,
                "last_seen": "2026-06-24T11:00:00+00:00",
                "failure_count": 0,
                "is_sensitive_resource": False,
            }
        ]
        g1 = self._build(edges)
        g2 = self._build(edges)
        assert sorted((e.source, e.target, e.relationship.value) for e in g1.edges) == sorted(
            (e.source, e.target, e.relationship.value) for e in g2.edges
        )
        assert set(g1.nodes) == set(g2.nodes)

    def test_non_ok_payload_is_noop(self):
        graph = UnifiedGraph()
        _add_cloud_audit_behavioral(graph, {"status": "skipped"}, "scan")
        _add_cloud_audit_behavioral(graph, None, "scan")
        assert len(list(graph.edges)) == 0

    def test_incomplete_record_skipped(self):
        graph = self._build([{"principal": "alice", "resource": "", "action": "GetObject"}])
        assert len(list(graph.edges)) == 0
