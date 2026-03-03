"""Tests for the 10 enterprise gap features.

Covers: RBAC, audit trail, exceptions, baseline comparison,
trend analysis, SIEM connectors, alert dedup, and API endpoints.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

# ── 1. RBAC Tests ───────────────────────────────────────────────────


class TestRBAC:
    """Test role-based access control."""

    def test_role_enum_values(self):
        from agent_bom.rbac import Role

        assert Role.ADMIN.value == "admin"
        assert Role.ANALYST.value == "analyst"
        assert Role.VIEWER.value == "viewer"

    def test_admin_has_all_permissions(self):
        from agent_bom.rbac import Role, check_permission

        for action in ["scan", "read", "fleet_write", "policy_write", "exception_approve", "config"]:
            assert check_permission(Role.ADMIN, action) is True

    def test_analyst_can_scan_and_read(self):
        from agent_bom.rbac import Role, check_permission

        assert check_permission(Role.ANALYST, "scan") is True
        assert check_permission(Role.ANALYST, "read") is True
        assert check_permission(Role.ANALYST, "exception_create") is True

    def test_analyst_cannot_write_fleet_or_policy(self):
        from agent_bom.rbac import Role, check_permission

        assert check_permission(Role.ANALYST, "fleet_write") is False
        assert check_permission(Role.ANALYST, "policy_write") is False
        assert check_permission(Role.ANALYST, "exception_approve") is False

    def test_viewer_read_only(self):
        from agent_bom.rbac import Role, check_permission

        assert check_permission(Role.VIEWER, "read") is True
        assert check_permission(Role.VIEWER, "scan") is False
        assert check_permission(Role.VIEWER, "fleet_write") is False
        assert check_permission(Role.VIEWER, "config") is False

    def test_unknown_action_denied(self):
        from agent_bom.rbac import Role, check_permission

        assert check_permission(Role.ADMIN, "nonexistent") is False

    def test_resolve_role_from_api_key(self):
        from agent_bom.rbac import configure_api_keys, resolve_role

        configure_api_keys({"key-abc": "analyst", "key-xyz": "admin"})
        assert resolve_role(api_key="key-abc").value == "analyst"
        assert resolve_role(api_key="key-xyz").value == "admin"
        configure_api_keys({})  # cleanup

    def test_resolve_role_from_header(self):
        from agent_bom.rbac import resolve_role

        assert resolve_role(role_header="viewer").value == "viewer"
        assert resolve_role(role_header="ANALYST").value == "analyst"

    def test_resolve_role_default(self):
        from agent_bom.rbac import resolve_role

        role = resolve_role()
        assert role.value == "viewer"  # least privilege default

    @patch.dict(os.environ, {"AGENT_BOM_DEFAULT_ROLE": "viewer"})
    def test_resolve_role_env_default(self):
        from agent_bom.rbac import resolve_role

        assert resolve_role().value == "viewer"

    def test_load_api_keys_from_env(self):
        from agent_bom.rbac import configure_api_keys, load_api_keys_from_env, resolve_role

        with patch.dict(os.environ, {"AGENT_BOM_API_KEYS": "k1:admin,k2:viewer"}):
            load_api_keys_from_env()
            assert resolve_role(api_key="k1").value == "admin"
            assert resolve_role(api_key="k2").value == "viewer"
        configure_api_keys({})  # cleanup


# ── 2. Audit Log Tests ─────────────────────────────────────────────


class TestAuditLog:
    """Test immutable audit trail."""

    def test_entry_auto_generates_id_and_timestamp(self):
        from agent_bom.api.audit_log import AuditEntry

        entry = AuditEntry(action="scan", actor="admin")
        assert entry.entry_id
        assert entry.timestamp

    def test_entry_hmac_signing(self):
        from agent_bom.api.audit_log import AuditEntry

        entry = AuditEntry(action="scan", actor="admin", resource="job/123")
        entry.sign()
        assert entry.hmac_signature
        assert entry.verify() is True

    def test_entry_tamper_detection(self):
        from agent_bom.api.audit_log import AuditEntry

        entry = AuditEntry(action="scan", actor="admin")
        entry.sign()
        entry.action = "policy_eval"  # tamper
        assert entry.verify() is False

    def test_inmemory_audit_append_and_list(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        log.append(AuditEntry(action="scan", actor="admin"))
        log.append(AuditEntry(action="fleet_change", actor="system"))
        entries = log.list_entries()
        assert len(entries) == 2

    def test_inmemory_audit_filter_by_action(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        log.append(AuditEntry(action="scan", actor="admin"))
        log.append(AuditEntry(action="alert", actor="system"))
        assert len(log.list_entries(action="scan")) == 1

    def test_inmemory_audit_filter_by_resource(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        log.append(AuditEntry(action="scan", resource="job/abc"))
        log.append(AuditEntry(action="scan", resource="job/xyz"))
        assert len(log.list_entries(resource="job/abc")) == 1

    def test_inmemory_audit_count(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        for _ in range(5):
            log.append(AuditEntry(action="scan"))
        assert log.count() == 5
        assert log.count(action="scan") == 5

    def test_inmemory_audit_verify_integrity(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        for i in range(10):
            log.append(AuditEntry(action="scan", actor=f"user-{i}"))
        verified, tampered = log.verify_integrity()
        assert verified == 10
        assert tampered == 0

    def test_sqlite_audit_roundtrip(self, tmp_path):
        from agent_bom.api.audit_log import AuditEntry, SQLiteAuditLog

        db = str(tmp_path / "audit.db")
        log = SQLiteAuditLog(db)
        log.append(AuditEntry(action="scan", actor="admin", resource="job/1", details={"packages": 42}))
        entries = log.list_entries()
        assert len(entries) == 1
        assert entries[0].action == "scan"
        assert entries[0].details == {"packages": 42}
        assert entries[0].verify() is True

    def test_log_action_convenience(self):
        from agent_bom.api.audit_log import InMemoryAuditLog, log_action, set_audit_log

        store = InMemoryAuditLog()
        set_audit_log(store)
        log_action("scan", actor="admin", resource="job/test", packages=42)
        entries = store.list_entries()
        assert len(entries) == 1
        assert entries[0].details == {"packages": 42}

    def test_audit_bounded_size(self):
        from agent_bom.api.audit_log import AuditEntry, InMemoryAuditLog

        log = InMemoryAuditLog()
        log._MAX_ENTRIES = 100
        for i in range(150):
            log.append(AuditEntry(action="scan"))
        assert log.count() <= 100


# ── 3. Exception Store Tests ───────────────────────────────────────


class TestExceptionStore:
    """Test vulnerability exception / waiver management."""

    def test_create_exception(self):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        exc = VulnException(vuln_id="CVE-2025-0001", package_name="requests", reason="Testing")
        assert exc.exception_id.startswith("exc-")
        assert exc.status == ExceptionStatus.PENDING

    def test_exception_matching(self):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        exc = VulnException(
            vuln_id="CVE-2025-0001",
            package_name="requests",
            status=ExceptionStatus.ACTIVE,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )
        assert exc.matches("CVE-2025-0001", "requests") is True
        assert exc.matches("CVE-2025-0002", "requests") is False
        assert exc.matches("CVE-2025-0001", "flask") is False

    def test_exception_wildcard_vuln(self):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        exc = VulnException(
            vuln_id="*",
            package_name="requests",
            status=ExceptionStatus.ACTIVE,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )
        assert exc.matches("CVE-2025-0001", "requests") is True
        assert exc.matches("CVE-9999-9999", "requests") is True
        assert exc.matches("CVE-2025-0001", "flask") is False

    def test_exception_expired(self):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        exc = VulnException(
            vuln_id="CVE-2025-0001",
            package_name="requests",
            status=ExceptionStatus.ACTIVE,
            expires_at=(datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
        )
        assert exc.is_expired() is True
        assert exc.matches("CVE-2025-0001", "requests") is False

    def test_pending_exception_does_not_match(self):
        from agent_bom.api.exception_store import ExceptionStatus, VulnException

        exc = VulnException(
            vuln_id="CVE-2025-0001",
            package_name="requests",
            status=ExceptionStatus.PENDING,
        )
        assert exc.matches("CVE-2025-0001", "requests") is False

    def test_inmemory_store_crud(self):
        from agent_bom.api.exception_store import InMemoryExceptionStore, VulnException

        store = InMemoryExceptionStore()
        exc = VulnException(vuln_id="CVE-1", package_name="pkg", reason="test")
        store.put(exc)
        assert store.get(exc.exception_id) is not None
        assert len(store.list_all()) == 1
        store.delete(exc.exception_id)
        assert store.get(exc.exception_id) is None

    def test_inmemory_store_find_matching(self):
        from agent_bom.api.exception_store import ExceptionStatus, InMemoryExceptionStore, VulnException

        store = InMemoryExceptionStore()
        exc = VulnException(
            vuln_id="CVE-1",
            package_name="pkg",
            status=ExceptionStatus.ACTIVE,
            expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat(),
        )
        store.put(exc)
        found = store.find_matching("CVE-1", "pkg")
        assert found is not None
        assert found.exception_id == exc.exception_id

    def test_sqlite_store_roundtrip(self, tmp_path):
        from agent_bom.api.exception_store import SQLiteExceptionStore, VulnException

        db = str(tmp_path / "exc.db")
        store = SQLiteExceptionStore(db)
        exc = VulnException(vuln_id="CVE-1", package_name="pkg", reason="test")
        store.put(exc)
        loaded = store.get(exc.exception_id)
        assert loaded is not None
        assert loaded.vuln_id == "CVE-1"

    def test_exception_to_dict(self):
        from agent_bom.api.exception_store import VulnException

        exc = VulnException(vuln_id="CVE-1", package_name="pkg")
        d = exc.to_dict()
        assert d["vuln_id"] == "CVE-1"
        assert d["status"] == "pending"
        json.dumps(d)  # serializable


# ── 4. Baseline Comparison Tests ───────────────────────────────────


class TestBaselineComparison:
    """Test scan-to-scan diff and trend analysis."""

    def _make_report(self, vulns: list[dict]) -> dict:
        return {"blast_radius": vulns}

    def _make_vuln(self, vuln_id: str, pkg: str, severity: str = "high") -> dict:
        return {
            "vulnerability_id": vuln_id,
            "package": pkg,
            "severity": severity,
            "risk_score": 7.5,
        }

    def test_new_vulns_detected(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "pkg-a")])
        curr = self._make_report([self._make_vuln("CVE-1", "pkg-a"), self._make_vuln("CVE-2", "pkg-b")])
        diff = compare_reports(prev, curr)
        assert diff.new_count == 1
        assert diff.new_vulns[0]["vulnerability_id"] == "CVE-2"

    def test_resolved_vulns_detected(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "pkg-a"), self._make_vuln("CVE-2", "pkg-b")])
        curr = self._make_report([self._make_vuln("CVE-1", "pkg-a")])
        diff = compare_reports(prev, curr)
        assert diff.resolved_count == 1
        assert diff.resolved_vulns[0]["vulnerability_id"] == "CVE-2"

    def test_persistent_vulns(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "pkg-a")])
        curr = self._make_report([self._make_vuln("CVE-1", "pkg-a")])
        diff = compare_reports(prev, curr)
        assert diff.persistent_count == 1
        assert diff.new_count == 0
        assert diff.resolved_count == 0

    def test_severity_change_detected(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "pkg-a", "medium")])
        curr = self._make_report([self._make_vuln("CVE-1", "pkg-a", "critical")])
        diff = compare_reports(prev, curr)
        assert len(diff.severity_changes) == 1
        assert diff.severity_changes[0]["previous_severity"] == "medium"
        assert diff.severity_changes[0]["current_severity"] == "critical"

    def test_improving_property(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "a"), self._make_vuln("CVE-2", "b")])
        curr = self._make_report([self._make_vuln("CVE-1", "a")])
        diff = compare_reports(prev, curr)
        assert diff.improving is True
        assert diff.net_change == -1

    def test_empty_reports(self):
        from agent_bom.baseline import compare_reports

        diff = compare_reports({}, {})
        assert diff.new_count == 0
        assert diff.resolved_count == 0

    def test_baseline_diff_to_dict(self):
        from agent_bom.baseline import compare_reports

        prev = self._make_report([self._make_vuln("CVE-1", "a")])
        curr = self._make_report([])
        diff = compare_reports(prev, curr)
        d = diff.to_dict()
        assert d["resolved_count"] == 1
        json.dumps(d)  # serializable


# ── 5. Trend Analysis Tests ────────────────────────────────────────


class TestTrendAnalysis:
    """Test historical trend tracking."""

    def test_inmemory_trend_record_and_history(self):
        from agent_bom.baseline import InMemoryTrendStore, TrendPoint

        store = InMemoryTrendStore()
        for i in range(5):
            store.record(
                TrendPoint(
                    timestamp=f"2026-03-0{i + 1}",
                    total_vulns=10 - i,
                    critical=1,
                    high=2,
                    medium=3,
                    low=4,
                    posture_score=80.0 + i,
                    posture_grade="B",
                )
            )
        history = store.get_history(limit=3)
        assert len(history) == 3
        # Most recent first
        assert history[0].timestamp == "2026-03-05"

    def test_sqlite_trend_store(self, tmp_path):
        from agent_bom.baseline import SQLiteTrendStore, TrendPoint

        db = str(tmp_path / "trend.db")
        store = SQLiteTrendStore(db)
        store.record(
            TrendPoint(
                timestamp="2026-03-01T00:00:00",
                total_vulns=10,
                critical=1,
                high=2,
                medium=3,
                low=4,
                posture_score=85.0,
                posture_grade="B",
            )
        )
        history = store.get_history()
        assert len(history) == 1
        assert history[0].total_vulns == 10

    def test_trend_point_to_dict(self):
        from agent_bom.baseline import TrendPoint

        p = TrendPoint(
            timestamp="2026-03-01",
            total_vulns=5,
            critical=1,
            high=1,
            medium=2,
            low=1,
            posture_score=80.0,
            posture_grade="B",
        )
        d = p.to_dict()
        assert d["total_vulns"] == 5
        json.dumps(d)

    def test_trend_bounded_size(self):
        from agent_bom.baseline import InMemoryTrendStore, TrendPoint

        store = InMemoryTrendStore()
        store._MAX_POINTS = 10
        for i in range(20):
            store.record(
                TrendPoint(
                    timestamp=f"2026-01-{i + 1:02d}",
                    total_vulns=i,
                    critical=0,
                    high=0,
                    medium=0,
                    low=0,
                    posture_score=50.0,
                    posture_grade="D",
                )
            )
        history = store.get_history(limit=100)
        assert len(history) <= 10


# ── 6. SIEM Connector Tests ────────────────────────────────────────


class TestSIEMConnectors:
    """Test SIEM integrations."""

    def test_list_connectors(self):
        from agent_bom.siem import list_connectors

        connectors = list_connectors()
        assert "splunk" in connectors
        assert "datadog" in connectors
        assert "elasticsearch" in connectors

    def test_create_unknown_connector_raises(self):
        from agent_bom.siem import SIEMConfig, create_connector

        with pytest.raises(ValueError, match="Unknown SIEM"):
            create_connector("oracle_siem", SIEMConfig(name="x", url="http://x"))

    @patch("httpx.post")
    def test_splunk_send_event(self, mock_post):
        from agent_bom.siem import SIEMConfig, SplunkHEC

        mock_post.return_value = MagicMock(status_code=200)
        connector = SplunkHEC(SIEMConfig(name="splunk", url="https://splunk:8088", token="tok"))
        result = connector.send_event({"type": "scan_alert", "severity": "critical"})
        assert result is True
        mock_post.assert_called_once()

    @patch("httpx.post")
    def test_datadog_send_event(self, mock_post):
        from agent_bom.siem import DatadogLogs, SIEMConfig

        mock_post.return_value = MagicMock(status_code=202)
        connector = DatadogLogs(SIEMConfig(name="datadog", url="https://intake.logs.dd.com", token="dd-key"))
        result = connector.send_event({"type": "scan_alert"})
        assert result is True

    @patch("httpx.post")
    def test_elasticsearch_send_event(self, mock_post):
        from agent_bom.siem import ElasticsearchConnector, SIEMConfig

        mock_post.return_value = MagicMock(status_code=201)
        connector = ElasticsearchConnector(SIEMConfig(name="es", url="https://es:9200", token="tok"))
        result = connector.send_event({"type": "scan_alert"})
        assert result is True

    @patch("httpx.post")
    def test_splunk_send_batch(self, mock_post):
        from agent_bom.siem import SIEMConfig, SplunkHEC

        mock_post.return_value = MagicMock(status_code=200)
        connector = SplunkHEC(SIEMConfig(name="splunk", url="https://splunk:8088", token="tok"))
        count = connector.send_batch([{"a": 1}, {"b": 2}, {"c": 3}])
        assert count == 3

    def test_create_from_env_none(self):
        from agent_bom.siem import create_from_env

        assert create_from_env() is None

    @patch.dict(
        os.environ,
        {
            "AGENT_BOM_SIEM_TYPE": "splunk",
            "AGENT_BOM_SIEM_URL": "https://splunk:8088",
            "AGENT_BOM_SIEM_TOKEN": "tok",
        },
    )
    def test_create_from_env_splunk(self):
        from agent_bom.siem import create_from_env

        connector = create_from_env()
        assert connector is not None


# ── 7. Alert Dedup Tests ───────────────────────────────────────────


class TestAlertDedup:
    """Test alert deduplication and suppression."""

    def _make_alert(self, vuln_id: str = "CVE-1", package: str = "pkg") -> dict:
        return {
            "type": "scan_alert",
            "severity": "critical",
            "detector": "scan_cve",
            "details": {"vuln_id": vuln_id, "package": package},
        }

    def test_first_alert_allowed(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator()
        assert dedup.should_send(self._make_alert()) is True

    def test_duplicate_suppressed(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator()
        alert = self._make_alert()
        dedup.should_send(alert)  # first: allowed
        assert dedup.should_send(alert) is False  # duplicate: suppressed

    def test_different_alerts_both_allowed(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator()
        assert dedup.should_send(self._make_alert("CVE-1", "pkg-a")) is True
        assert dedup.should_send(self._make_alert("CVE-2", "pkg-b")) is True

    def test_expired_window_resets(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator(suppression_window_seconds=0)  # instant expiry
        alert = self._make_alert()
        dedup.should_send(alert)
        # Window is 0 seconds, so next call should be after the window
        assert dedup.should_send(alert) is True

    def test_fingerprint_deterministic(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator()
        alert = self._make_alert()
        fp1 = dedup.fingerprint(alert)
        fp2 = dedup.fingerprint(alert)
        assert fp1 == fp2

    def test_stats(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator()
        alert = self._make_alert()
        dedup.should_send(alert)
        dedup.should_send(alert)
        dedup.should_send(alert)
        stats = dedup.get_stats()
        assert stats["tracked_fingerprints"] == 1
        assert stats["total_suppressed"] == 2

    def test_bounded_entries(self):
        from agent_bom.alerts.dedup import AlertDeduplicator

        dedup = AlertDeduplicator(max_entries=5)
        for i in range(10):
            dedup.should_send(self._make_alert(f"CVE-{i}", f"pkg-{i}"))
        stats = dedup.get_stats()
        assert stats["tracked_fingerprints"] <= 5
