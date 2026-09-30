"""Databricks SQL transport: bound values, bounded writes, honest outcomes."""

import json

import httpx
import pytest

from agent_bom.export.databricks_statement import DatabricksStatementConnection
from agent_bom.export.destinations import DatabricksWarehouseDestination, ExportDestinationError, ExportPublicationIndeterminateError


def connection(handler):
    return DatabricksStatementConnection(
        "workspace.cloud.databricks.com",
        "/sql/1.0/warehouses/abc123",
        "private-token",
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )


def success(rows=None):
    return httpx.Response(200, json={"statement_id": "stmt-1", "status": {"state": "SUCCEEDED"}, "result": {"data_array": rows or []}})


def test_parameters_never_enter_sql_or_change_quoted_identifiers():
    requests = []

    def handler(request):
        requests.append(request)
        return success([["1"]])

    conn = connection(handler)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM `catalog?`.`schema``?`.`table` WHERE `tenant_id` = ? AND `score` = ?", ("x'); DROP TABLE t;--", None))
    body = json.loads(requests[0].content)
    assert body["statement"] == "SELECT 1 FROM `catalog?`.`schema``?`.`table` WHERE `tenant_id` = :p0 AND `score` = :p1"
    assert body["parameters"] == [
        {"name": "p0", "value": "x'); DROP TABLE t;--", "type": "STRING"},
        {"name": "p1", "value": None, "type": "STRING"},
    ]
    assert cursor.fetchone() == ["1"]
    assert cursor.fetchone() is None
    assert requests[0].headers["authorization"] == "Bearer private-token"
    conn.close()


def test_batches_are_bounded_and_preserve_null_and_measured_zero():
    bodies = []

    def handler(request):
        bodies.append(json.loads(request.content))
        return success()

    conn = connection(handler)
    conn.cursor().executemany("INSERT INTO `feed` (`id`, `score`) VALUES (?, ?)", [(str(i), None if i == 0 else 0.0) for i in range(205)])
    assert [len(b["parameters"]) for b in bodies] == [200, 200, 10]
    assert bodies[0]["parameters"][1]["value"] is None
    assert bodies[0]["parameters"][3] == {"name": "p3", "value": "0.0", "type": "DOUBLE"}


@pytest.mark.parametrize(
    "response",
    [
        {"status": {"state": "FAILED", "error": {"message": "private-token"}}},
        {},
        {"status": {"state": "SUCCEEDED"}, "manifest": {"truncated": True}},
    ],
)
def test_invalid_or_failed_result_never_reports_success_or_leaks_provider_text(response):
    conn = connection(lambda _: httpx.Response(200, json=response))
    with pytest.raises(ExportDestinationError) as error:
        conn.cursor().execute("SELECT 1")
    assert "private-token" not in str(error.value)


def test_transport_timeout_does_not_resubmit_mutating_statement():
    calls = []

    def handler(request):
        calls.append(request)
        raise httpx.ReadTimeout("private-token", request=request)

    with pytest.raises(ExportDestinationError, match="Databricks statement request failed"):
        connection(handler).cursor().execute("INSERT INTO `t` VALUES (?)", ("value",))
    assert len(calls) == 1


def test_async_completion_polls_same_statement_without_resubmission(monkeypatch):
    calls = []
    monkeypatch.setattr("agent_bom.export.databricks_statement.time.sleep", lambda _: None)

    def handler(request):
        calls.append(request)
        if request.method == "POST":
            return httpx.Response(200, json={"statement_id": "stmt-1", "status": {"state": "RUNNING"}})
        return success()

    connection(handler).cursor().execute("INSERT INTO `t` VALUES (?)", ("value",))
    assert [r.method for r in calls] == ["POST", "GET"]
    assert calls[1].url.path == "/api/2.0/sql/statements/stmt-1"


def test_lost_publication_response_reconciles_exact_attempt_and_keeps_staging():
    bodies = []

    def handler(request):
        body = json.loads(request.content)
        bodies.append(body)
        if body["statement"].startswith("INSERT INTO `main`.`sec`.`findings_feed_runs`"):
            raise httpx.ReadTimeout("secret", request=request)
        return success([["1"]] if body["statement"].startswith("SELECT 1") else [])

    conn = connection(handler)
    result = DatabricksWarehouseDestination(lambda: conn, catalog="main", schema="sec").write_findings(
        [{"finding_id": "f1"}],
        tenant_id="tenant-a",
        run_id="run-a",
    )
    assert result.row_count == 1
    assert not any(b["statement"].startswith("DELETE") for b in bodies)
    lookup = bodies[-1]
    assert [p["value"] for p in lookup["parameters"][:2]] == ["tenant-a", "run-a"]
    assert lookup["parameters"][2]["value"] == bodies[-2]["parameters"][2]["value"]


@pytest.mark.parametrize(
    "host,path",
    [
        ("https://evil.test/path", "/sql/1.0/warehouses/id"),
        ("good.test@evil.test", "/sql/1.0/warehouses/id"),
        ("good.test", "/sql/protocolv1/o/1/cluster"),
    ],
)
def test_invalid_endpoint_rejected_before_request(host, path):
    with pytest.raises(ExportDestinationError):
        DatabricksStatementConnection(host, path, "token")


def test_default_export_factory_uses_statement_transport(monkeypatch):
    from agent_bom.export.destinations import _default_databricks_connection

    client = httpx.Client(transport=httpx.MockTransport(lambda _: success()))
    monkeypatch.setattr("agent_bom.export.databricks_statement.create_sync_client", lambda **_: client)
    conn = _default_databricks_connection({"server_hostname": "workspace.test", "http_path": "/sql/1.0/warehouses/id"}, "token")
    assert isinstance(conn, DatabricksStatementConnection)
    conn.cursor().execute("SELECT 1")
    conn.close()


def test_pending_statement_is_cancelled_at_deadline_but_not_claimed_rolled_back(monkeypatch):
    calls = []
    times = iter([0, 121])
    monkeypatch.setattr("agent_bom.export.databricks_statement.time.monotonic", lambda: next(times))

    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"statement_id": "stmt-1", "status": {"state": "RUNNING"}})

    with pytest.raises(ExportDestinationError, match="indeterminate"):
        connection(handler).cursor().execute("INSERT INTO `t` VALUES (?)", ("value",))
    assert len(calls) == 2
    assert calls[1].url.path.endswith("/stmt-1/cancel")


def test_missing_publication_marker_after_response_loss_preserves_staging():
    statements = []

    def handler(request):
        statement = json.loads(request.content)["statement"]
        statements.append(statement)
        if statement.startswith("INSERT INTO `main`.`sec`.`findings_feed_runs`"):
            raise httpx.ReadTimeout("secret", request=request)
        return success()

    with pytest.raises(ExportPublicationIndeterminateError):
        DatabricksWarehouseDestination(lambda: connection(handler), catalog="main", schema="sec").write_findings(
            [{"finding_id": "f1"}],
            tenant_id="tenant-a",
            run_id="run-a",
        )
    assert not any(s.startswith("DELETE") for s in statements)


def test_mismatched_poll_identity_fails_closed(monkeypatch):
    monkeypatch.setattr("agent_bom.export.databricks_statement.time.sleep", lambda _: None)

    def handler(request):
        if request.method == "POST":
            return httpx.Response(200, json={"statement_id": "wrong-id", "status": {"state": "RUNNING"}})
        return success()

    with pytest.raises(ExportDestinationError, match="mismatched statement identity"):
        connection(handler).cursor().execute("SELECT 1")


@pytest.mark.parametrize("rows", [[[]], [["0"]], ["1"], [["1"], ["1"]]])
def test_malformed_publication_marker_is_not_evidence_of_commit(rows):
    with pytest.raises(ExportDestinationError, match="invalid publication marker"):
        connection(lambda _: success(rows)).cursor().execute("SELECT 1 FROM `feed_runs` LIMIT 1")


def test_oversized_request_fails_before_network(monkeypatch):
    monkeypatch.setattr("agent_bom.export.databricks_statement._MAX_BODY_BYTES", 100)
    calls = []
    conn = connection(lambda request: calls.append(request) or success())
    with pytest.raises(ExportDestinationError, match="bounded request size"):
        conn.cursor().execute("INSERT INTO `t` VALUES (?)", ("x" * 101,))
    assert calls == []


def test_redirect_never_forwards_stored_token_to_another_host():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(307, headers={"Location": "https://other.test/steal"})

    with pytest.raises(ExportDestinationError):
        connection(handler).cursor().execute("SELECT 1")
    assert len(calls) == 1
    assert calls[0].url.host == "workspace.cloud.databricks.com"
