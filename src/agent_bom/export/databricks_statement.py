"""Bounded SQL warehouse writes through Databricks' Statement Execution API.

This is the small cursor surface used by the findings exporter, not a general
DBAPI driver. Values stay server-bound; accepted writes are never resubmitted.
"""

from __future__ import annotations

import json
import math
import re
import time
from collections.abc import Iterable, Sequence
from typing import Any

import httpx

from agent_bom.export.destinations import ExportDestinationError
from agent_bom.http_client import create_sync_client

_HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?")
_WAREHOUSE = re.compile(r"/sql/1\.0/warehouses/([A-Za-z0-9-]+)")
_MARKER = re.compile(r"`(?:``|[^`])*`|\?")
_VALUES = re.compile(r" VALUES (\(\?(?:, \?)*\))$")
_MAX_BODY_BYTES = 8 * 1024 * 1024


def _parameters(statement: str, values: Sequence[Any]) -> tuple[str, list[dict[str, Any]]]:
    parameters: list[dict[str, Any]] = []

    def replace(match: re.Match[str]) -> str:
        if match.group() != "?":
            return match.group()
        index = len(parameters)
        if index >= len(values):
            raise ExportDestinationError("Databricks parameter count mismatch")
        value = values[index]
        kind = "STRING"
        if isinstance(value, bool):
            kind, value = "BOOLEAN", str(value).lower()
        elif isinstance(value, int):
            kind = "BIGINT"
        elif isinstance(value, float):
            if not math.isfinite(value):
                raise ExportDestinationError("Databricks numeric parameter must be finite")
            kind = "DOUBLE"
        elif value is not None and not isinstance(value, str):
            raise ExportDestinationError("Unsupported Databricks parameter type")
        parameters.append({"name": f"p{index}", "value": None if value is None else str(value), "type": kind})
        return f":p{index}"

    bound = _MARKER.sub(replace, statement)
    if len(parameters) != len(values):
        raise ExportDestinationError("Databricks parameter count mismatch")
    return bound, parameters


class DatabricksStatementConnection:
    def __init__(self, host: str, http_path: str, token: str, *, client: httpx.Client | None = None) -> None:
        warehouse = _WAREHOUSE.fullmatch(http_path)
        if not _HOST.fullmatch(host) or not warehouse or not token.strip():
            raise ExportDestinationError("Databricks export requires a hostname, SQL warehouse HTTP path, and stored token")
        self.warehouse_id = warehouse.group(1)
        self._url = f"https://{host}/api/2.0/sql/statements"
        self._headers = {"Authorization": f"Bearer {token}"}
        self._client = client if client is not None else create_sync_client(timeout=60)

    def cursor(self) -> DatabricksStatementCursor:
        return DatabricksStatementCursor(self)

    def close(self) -> None:
        self._client.close()

    def request(self, method: str, suffix: str = "", *, body: dict[str, Any] | None = None, timeout: float = 60) -> dict[str, Any]:
        try:
            response = self._client.request(
                method,
                self._url + suffix,
                headers=self._headers,
                json=body,
                timeout=timeout,
                follow_redirects=False,
            )
            response.raise_for_status()
            result = response.json()
            if not isinstance(result, dict):
                raise ValueError("Invalid response shape")
            return result
        except (httpx.HTTPError, ValueError):
            # Provider text and request URLs can contain credentials or identifiers.
            raise ExportDestinationError("Databricks statement request failed") from None


class DatabricksStatementCursor:
    def __init__(self, connection: DatabricksStatementConnection) -> None:
        self._connection = connection
        self._rows: list[Any] = []

    def execute(self, statement: str, values: Sequence[Any] = ()) -> None:
        self._rows = []
        statement, parameters = _parameters(statement, values)
        body = {
            "warehouse_id": self._connection.warehouse_id,
            "statement": statement,
            "parameters": parameters,
            "wait_timeout": "10s",
            "on_wait_timeout": "CONTINUE",
            "disposition": "INLINE",
            "format": "JSON_ARRAY",
        }
        if len(json.dumps(body).encode()) > _MAX_BODY_BYTES:
            raise ExportDestinationError("Databricks statement exceeds the bounded request size")
        deadline = time.monotonic() + 120
        result = self._connection.request("POST", body=body)
        result = self._await_completion(result, deadline)
        manifest = result.get("manifest") or {}
        payload = result.get("result") or {}
        rows = payload.get("data_array", []) if isinstance(payload, dict) else None
        if not isinstance(manifest, dict) or manifest.get("truncated") or not isinstance(rows, list):
            raise ExportDestinationError("Databricks returned incomplete statement results")
        # Export statements return no rows, except SELECT 1 ... LIMIT 1 used to
        # reconcile publication. Additional chunks would violate that contract.
        if payload.get("next_chunk_index") is not None:
            raise ExportDestinationError("Databricks returned unexpected result chunks")
        if statement.startswith("SELECT 1") and rows not in ([], [["1"]]):
            raise ExportDestinationError("Databricks returned an invalid publication marker")
        self._rows = rows

    def _await_completion(self, result: dict[str, Any], deadline: float) -> dict[str, Any]:
        statement_id: str | None = None
        for _ in range(120):
            status = result.get("status")
            state = status.get("state") if isinstance(status, dict) else None
            if state not in {"PENDING", "RUNNING", "SUCCEEDED"}:
                raise ExportDestinationError("Databricks statement did not succeed")
            current_id = result.get("statement_id")
            if not isinstance(current_id, str) or not re.fullmatch(r"[A-Za-z0-9-]+", current_id):
                raise ExportDestinationError("Databricks statement status is incomplete")
            if statement_id is not None and current_id != statement_id:
                raise ExportDestinationError("Databricks returned a mismatched statement identity")
            statement_id = current_id
            if state == "SUCCEEDED":
                return result
            remaining = deadline - time.monotonic()
            if remaining <= 1:
                break
            time.sleep(1)
            result = self._connection.request("GET", f"/{statement_id}", timeout=min(60, remaining))
        if statement_id is not None:
            try:
                self._connection.request("POST", f"/{statement_id}/cancel", timeout=5)
            except ExportDestinationError:
                pass  # Cancellation is best effort; it never proves rollback.
        raise ExportDestinationError("Databricks statement completion is indeterminate")

    def executemany(self, statement: str, rows: Iterable[Sequence[Any]]) -> None:
        match = _VALUES.search(statement)
        if not match:
            raise ExportDestinationError("Databricks batch requires a parameterized VALUES insert")
        batch: list[Sequence[Any]] = []
        for row in rows:
            batch.append(row)
            if len(batch) == 100:
                self._insert_batch(statement, match, batch)
                batch = []
        if batch:
            self._insert_batch(statement, match, batch)

    def _insert_batch(self, statement: str, match: re.Match[str], batch: list[Sequence[Any]]) -> None:
        columns = match.group(1).count("?")
        if any(len(row) != columns for row in batch):
            raise ExportDestinationError("Databricks parameter count mismatch")
        combined = statement[: match.start(1)] + ", ".join([match.group(1)] * len(batch))
        self.execute(combined, tuple(value for row in batch for value in row))

    def fetchone(self) -> Any:
        return self._rows.pop(0) if self._rows else None

    def close(self) -> None:
        self._rows = []
