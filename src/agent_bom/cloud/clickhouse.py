"""Zero-dependency ClickHouse HTTP API client for analytics.

Uses only stdlib ``urllib.request`` — no pip packages required.
Designed for append-only OLAP workloads (vulnerability trends, runtime events,
posture snapshots).  OLTP stays in Postgres/SQLite.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

_DEFAULT_TIMEOUT = 30  # seconds


class ClickHouseError(Exception):
    """Raised when a ClickHouse HTTP request fails."""


class ClickHouseClient:
    """Zero-dependency ClickHouse HTTP API client."""

    def __init__(
        self,
        url: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str = "agent_bom",
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> None:
        self.url = (url or os.environ.get("AGENT_BOM_CLICKHOUSE_URL", "")).rstrip("/")
        if not self.url:
            raise ClickHouseError("ClickHouse URL required. Set AGENT_BOM_CLICKHOUSE_URL or pass url=.")
        self.user = user or os.environ.get("AGENT_BOM_CLICKHOUSE_USER", "default")
        self.password = password or os.environ.get("AGENT_BOM_CLICKHOUSE_PASSWORD", "")
        self.database = database
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Core HTTP interface
    # ------------------------------------------------------------------

    def execute(self, query: str) -> str:
        """Execute a query, return raw response text."""
        headers = {
            "X-ClickHouse-User": self.user,
            "X-ClickHouse-Key": self.password,
            "X-ClickHouse-Database": self.database,
        }
        data = query.encode("utf-8")
        req = urllib.request.Request(self.url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # nosec B310 — URL scheme is user-configured
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise ClickHouseError(f"ClickHouse HTTP {exc.code}: {body[:500]}") from exc
        except urllib.error.URLError as exc:
            raise ClickHouseError(f"ClickHouse connection error: {exc.reason}") from exc
        except TimeoutError as exc:
            raise ClickHouseError(f"ClickHouse request timed out after {self.timeout}s") from exc

    def insert_json(self, table: str, rows: list[dict[str, Any]]) -> None:
        """Batch insert rows via FORMAT JSONEachRow."""
        if not rows:
            return
        ndjson = "\n".join(json.dumps(r, default=str) for r in rows)
        query = f"INSERT INTO {table} FORMAT JSONEachRow\n{ndjson}"
        self.execute(query)

    def query_json(self, query: str) -> list[dict[str, Any]]:
        """Execute SELECT, return parsed JSON rows."""
        if not query.rstrip().upper().endswith("FORMAT JSON"):
            query = query.rstrip().rstrip(";") + " FORMAT JSON"
        raw = self.execute(query)
        parsed = json.loads(raw)
        return parsed.get("data", [])

    # ------------------------------------------------------------------
    # Schema management
    # ------------------------------------------------------------------

    def ensure_tables(self) -> None:
        """Create analytics tables if they don't exist (idempotent)."""
        self.execute(f"CREATE DATABASE IF NOT EXISTS {self.database}")
        for ddl in _TABLE_DDL:
            self.execute(ddl)
        logger.info("ClickHouse analytics tables ensured in database '%s'", self.database)


# ------------------------------------------------------------------
# Table definitions
# ------------------------------------------------------------------

_TABLE_DDL: list[str] = [
    # 1. Vulnerability scan results (append-only)
    """\
CREATE TABLE IF NOT EXISTS vulnerability_scans (
    scan_id String,
    scan_timestamp DateTime DEFAULT now(),
    package_name String,
    package_version String,
    ecosystem LowCardinality(String),
    cve_id String,
    cvss_score Float32,
    epss_score Float32,
    severity LowCardinality(String),
    source LowCardinality(String),
    agent_name String,
    environment LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, severity, agent_name)
PARTITION BY toYYYYMM(scan_timestamp)""",
    # 2. Runtime protection events (append-only)
    """\
CREATE TABLE IF NOT EXISTS runtime_events (
    event_id String,
    event_timestamp DateTime DEFAULT now(),
    event_type LowCardinality(String),
    detector LowCardinality(String),
    severity LowCardinality(String),
    tool_name String,
    message String,
    agent_name String
) ENGINE = MergeTree()
ORDER BY (event_timestamp, event_type, agent_name)
PARTITION BY toYYYYMM(event_timestamp)""",
    # 3. Posture scores (periodic snapshots)
    """\
CREATE TABLE IF NOT EXISTS posture_scores (
    measured_at DateTime DEFAULT now(),
    agent_name String,
    total_packages UInt32,
    critical_vulns UInt32,
    high_vulns UInt32,
    medium_vulns UInt32,
    posture_grade LowCardinality(String),
    risk_score Float32,
    compliance_score Float32
) ENGINE = MergeTree()
ORDER BY (measured_at, agent_name)
PARTITION BY toYYYYMM(measured_at)
TTL measured_at + INTERVAL 2 YEAR""",
    # 4. Scan metadata (one row per scan run)
    """\
CREATE TABLE IF NOT EXISTS scan_metadata (
    scan_id String,
    scan_timestamp DateTime DEFAULT now(),
    agent_count UInt32,
    package_count UInt32,
    vuln_count UInt32,
    critical_count UInt32,
    high_count UInt32,
    posture_grade LowCardinality(String),
    scan_duration_ms UInt32,
    source LowCardinality(String)
) ENGINE = MergeTree()
ORDER BY (scan_timestamp, scan_id)
PARTITION BY toYYYYMM(scan_timestamp)
TTL scan_timestamp + INTERVAL 2 YEAR""",
]
