"""Local scan analytics store.

The history JSON files remain the durable artifact of record. This module keeps
an adjacent queryable mirror of scan runs, findings, and packages so local
reporting can read small normalized tables instead of repeatedly loading every
history JSON file.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import uuid
from collections import defaultdict
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from agent_bom.analytics_retention import (
    analytics_max_events,
    analytics_max_findings,
    analytics_max_packages,
    plan_local_scan_prune,
    prune_local_scan_runs,
)
from agent_bom.canonical_ids import canonical_package_id
from agent_bom.config import LOCAL_ANALYTICS_DB

SCHEMA_VERSION = 4
DEFAULT_LOCAL_ANALYTICS_PATH = Path.home() / ".agent-bom" / "local-analytics.sqlite"


def local_analytics_path() -> Path:
    """Return the configured local analytics database path."""
    if LOCAL_ANALYTICS_DB:
        return Path(LOCAL_ANALYTICS_DB).expanduser()
    return DEFAULT_LOCAL_ANALYTICS_PATH


class LocalAnalyticsStore:
    """Small local SQL mirror of scan history."""

    def __init__(self, db_path: str | Path | None = None) -> None:
        self.db_path = Path(db_path).expanduser() if db_path is not None else local_analytics_path()

    def _connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema(conn)
        return conn

    def _init_schema(self, conn: sqlite3.Connection) -> None:
        if _table_exists(conn, "scan_runs") and "run_id" not in _table_columns(conn, "scan_runs"):
            self._migrate_v1_schema(conn)
        self._create_schema(conn)
        self._migrate_canonical_columns(conn)
        self._migrate_retention_columns(conn)
        conn.execute(
            """
            INSERT INTO local_schema_meta(component, version, applied_at)
            VALUES ('local_analytics', ?, ?)
            ON CONFLICT(component) DO UPDATE SET
                version = excluded.version,
                applied_at = excluded.applied_at
            """,
            (SCHEMA_VERSION, _now_iso()),
        )
        conn.commit()

    def _create_schema(self, conn: sqlite3.Connection) -> None:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS local_schema_meta (
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL,
                applied_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scan_runs (
                run_id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                generated_at TEXT NOT NULL,
                recorded_at TEXT NOT NULL,
                tenant_id TEXT NOT NULL DEFAULT 'default',
                source TEXT NOT NULL,
                artifact_path TEXT,
                total_agents INTEGER NOT NULL DEFAULT 0,
                total_packages INTEGER NOT NULL DEFAULT 0,
                total_vulnerabilities INTEGER NOT NULL DEFAULT 0,
                critical_findings INTEGER NOT NULL DEFAULT 0,
                high_findings INTEGER NOT NULL DEFAULT 0,
                finding_rows INTEGER NOT NULL DEFAULT 0,
                package_rows INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS scan_findings (
                run_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                finding_key TEXT NOT NULL,
                vulnerability_id TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_ref TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                severity TEXT NOT NULL,
                risk_score REAL NOT NULL DEFAULT 0,
                schema_version TEXT NOT NULL DEFAULT '',
                finding_type TEXT NOT NULL DEFAULT '',
                source TEXT NOT NULL DEFAULT '',
                title TEXT NOT NULL DEFAULT '',
                asset_json TEXT NOT NULL DEFAULT '{}',
                raw_json TEXT NOT NULL DEFAULT '{}',
                canonical_id TEXT NOT NULL DEFAULT '',
                asset_canonical_id TEXT NOT NULL DEFAULT '',
                affected_agents_json TEXT NOT NULL DEFAULT '[]',
                affected_servers_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY (run_id, finding_key),
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS scan_packages (
                run_id TEXT NOT NULL,
                scan_id TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                server_name TEXT NOT NULL,
                package_name TEXT NOT NULL,
                package_version TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                purl TEXT,
                package_canonical_id TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (run_id, agent_name, server_name, package_name, package_version, ecosystem),
                FOREIGN KEY (run_id) REFERENCES scan_runs(run_id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scan_runs_generated_at ON scan_runs(generated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_scan_runs_scan_id ON scan_runs(scan_id);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_severity ON scan_findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_source ON scan_findings(source);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_type ON scan_findings(finding_type);
            CREATE INDEX IF NOT EXISTS idx_scan_packages_name ON scan_packages(package_name);
            """
        )

    def _migrate_canonical_columns(self, conn: sqlite3.Connection) -> None:
        finding_columns = _table_columns(conn, "scan_findings") if _table_exists(conn, "scan_findings") else set()
        package_columns = _table_columns(conn, "scan_packages") if _table_exists(conn, "scan_packages") else set()
        if "canonical_id" not in finding_columns:
            conn.execute("ALTER TABLE scan_findings ADD COLUMN canonical_id TEXT NOT NULL DEFAULT ''")
        if "asset_canonical_id" not in finding_columns:
            conn.execute("ALTER TABLE scan_findings ADD COLUMN asset_canonical_id TEXT NOT NULL DEFAULT ''")
        if "package_canonical_id" not in package_columns:
            conn.execute("ALTER TABLE scan_packages ADD COLUMN package_canonical_id TEXT NOT NULL DEFAULT ''")
        conn.executescript(
            """
            CREATE INDEX IF NOT EXISTS idx_scan_findings_canonical_id ON scan_findings(canonical_id);
            CREATE INDEX IF NOT EXISTS idx_scan_findings_asset_canonical_id ON scan_findings(asset_canonical_id);
            CREATE INDEX IF NOT EXISTS idx_scan_packages_canonical_id ON scan_packages(package_canonical_id);
            """
        )

    def _migrate_retention_columns(self, conn: sqlite3.Connection) -> None:
        columns = _table_columns(conn, "scan_runs")
        added_finding_rows = "finding_rows" not in columns
        added_package_rows = "package_rows" not in columns
        if added_finding_rows:
            conn.execute("ALTER TABLE scan_runs ADD COLUMN finding_rows INTEGER NOT NULL DEFAULT 0")
        if added_package_rows:
            conn.execute("ALTER TABLE scan_runs ADD COLUMN package_rows INTEGER NOT NULL DEFAULT 0")
        if added_finding_rows:
            conn.execute(
                """
                UPDATE scan_runs
                SET finding_rows = (
                    SELECT COUNT(*) FROM scan_findings WHERE scan_findings.run_id = scan_runs.run_id
                )
                """
            )
        if added_package_rows:
            conn.execute(
                """
                UPDATE scan_runs
                SET package_rows = (
                    SELECT COUNT(*) FROM scan_packages WHERE scan_packages.run_id = scan_runs.run_id
                )
                """
            )

    def _migrate_v1_schema(self, conn: sqlite3.Connection) -> None:
        """Move the initial artifact-keyed mirror into run-keyed tables."""
        conn.execute("PRAGMA foreign_keys=OFF")
        conn.execute("ALTER TABLE scan_runs RENAME TO scan_runs_v1")
        conn.execute("ALTER TABLE scan_findings RENAME TO scan_findings_v1")
        conn.execute("ALTER TABLE scan_packages RENAME TO scan_packages_v1")
        self._create_schema(conn)
        conn.execute(
            """
            INSERT INTO scan_runs(
                run_id, scan_id, generated_at, recorded_at, tenant_id, source, artifact_path,
                total_agents, total_packages, total_vulnerabilities, critical_findings, high_findings
            )
            SELECT scan_id, scan_id, generated_at, recorded_at, tenant_id, source, artifact_path,
                   total_agents, total_packages, total_vulnerabilities, critical_findings, high_findings
            FROM scan_runs_v1
            """
        )
        conn.execute(
            """
            INSERT INTO scan_findings(
                run_id, scan_id, finding_key, vulnerability_id, package_name, package_version,
                package_ref, ecosystem, severity, risk_score, affected_agents_json, affected_servers_json
            )
            SELECT scan_id, scan_id, finding_key, vulnerability_id, package_name, package_version,
                   package_ref, ecosystem, severity, risk_score, affected_agents_json, affected_servers_json
            FROM scan_findings_v1
            """
        )
        conn.execute(
            """
            INSERT INTO scan_packages(
                run_id, scan_id, agent_name, server_name, package_name, package_version, ecosystem, purl
            )
            SELECT scan_id, scan_id, agent_name, server_name, package_name, package_version, ecosystem, purl
            FROM scan_packages_v1
            """
        )
        conn.execute(
            """
            UPDATE scan_runs
            SET finding_rows = (
                    SELECT COUNT(*) FROM scan_findings WHERE scan_findings.run_id = scan_runs.run_id
                ),
                package_rows = (
                    SELECT COUNT(*) FROM scan_packages WHERE scan_packages.run_id = scan_runs.run_id
                )
            """
        )
        conn.execute("DROP TABLE scan_findings_v1")
        conn.execute("DROP TABLE scan_packages_v1")
        conn.execute("DROP TABLE scan_runs_v1")
        conn.execute("PRAGMA foreign_keys=ON")

    def record_scan_report(
        self,
        report_json: dict[str, Any],
        *,
        source: str,
        tenant_id: str = "default",
        artifact_path: str | Path | None = None,
    ) -> str:
        """Upsert one scan report into normalized local tables."""
        scan_id = str(report_json.get("scan_id") or "").strip()
        if not scan_id:
            generated_key = str(report_json.get("generated_at") or _now_iso()).replace(":", "").replace("-", "")
            scan_id = f"local-{generated_key}"

        generated_at = str(report_json.get("generated_at") or report_json.get("scan_timestamp") or _now_iso())
        recorded_at = _now_iso()
        run_id = _run_id(report_json)
        raw_summary = report_json.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        findings = list(_iter_findings(report_json))
        finding_rows = _finding_rows(run_id, scan_id, findings)
        package_rows = list(_iter_packages(report_json))

        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO scan_runs(
                    run_id, scan_id, generated_at, recorded_at, tenant_id, source, artifact_path,
                    total_agents, total_packages, total_vulnerabilities, critical_findings, high_findings,
                    finding_rows, package_rows
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(run_id) DO UPDATE SET
                    scan_id = excluded.scan_id,
                    generated_at = excluded.generated_at,
                    recorded_at = excluded.recorded_at,
                    tenant_id = excluded.tenant_id,
                    source = excluded.source,
                    artifact_path = excluded.artifact_path,
                    total_agents = excluded.total_agents,
                    total_packages = excluded.total_packages,
                    total_vulnerabilities = excluded.total_vulnerabilities,
                    critical_findings = excluded.critical_findings,
                    high_findings = excluded.high_findings,
                    finding_rows = excluded.finding_rows,
                    package_rows = excluded.package_rows
                """,
                (
                    run_id,
                    scan_id,
                    generated_at,
                    recorded_at,
                    tenant_id or "default",
                    source,
                    str(artifact_path) if artifact_path is not None else None,
                    _int(summary.get("total_agents")),
                    _int(summary.get("total_packages")),
                    _int(summary.get("total_vulnerabilities")),
                    _int(summary.get("critical_findings")),
                    sum(1 for row in finding_rows if row[8] == "high"),
                    len(finding_rows),
                    len(package_rows),
                ),
            )
            conn.execute("DELETE FROM scan_findings WHERE run_id = ?", (run_id,))
            conn.execute("DELETE FROM scan_packages WHERE run_id = ?", (run_id,))
            conn.executemany(
                """
                INSERT INTO scan_findings(
                    run_id, scan_id, finding_key, vulnerability_id, package_name, package_version,
                    package_ref, ecosystem, severity, risk_score,
                    schema_version, finding_type, source, title, asset_json, raw_json,
                    canonical_id, asset_canonical_id, affected_agents_json, affected_servers_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                finding_rows,
            )
            conn.executemany(
                """
                INSERT INTO scan_packages(
                    run_id, scan_id, agent_name, server_name, package_name, package_version, ecosystem, purl,
                    package_canonical_id
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [_package_row(run_id, scan_id, package_row) for package_row in package_rows],
            )
            prune_local_scan_runs(conn)
            conn.commit()
        return scan_id

    def list_scan_runs(self, *, limit: int = 20, tenant_id: str | None = None) -> list[dict[str, Any]]:
        """Return recent scan runs newest first."""
        with closing(self._connect()) as conn:
            tenant_filter = (tenant_id or "").strip()
            bounded_limit = max(1, int(limit))
            if tenant_filter:
                rows = conn.execute(
                    """
                    SELECT run_id, scan_id, generated_at, recorded_at, tenant_id, source, artifact_path,
                           total_agents, total_packages, total_vulnerabilities,
                           critical_findings, high_findings
                    FROM scan_runs
                    WHERE tenant_id = ?
                    ORDER BY generated_at DESC
                    LIMIT ?
                    """,
                    (tenant_filter, bounded_limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT run_id, scan_id, generated_at, recorded_at, tenant_id, source, artifact_path,
                           total_agents, total_packages, total_vulnerabilities,
                           critical_findings, high_findings
                    FROM scan_runs
                    ORDER BY generated_at DESC
                    LIMIT ?
                    """,
                    (bounded_limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    def storage_stats(self) -> dict[str, Any]:
        """Return bounded local-mirror usage without including deployment state."""
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT
                    COUNT(*) AS scan_runs,
                    COALESCE(SUM(finding_rows), 0) AS findings,
                    COALESCE(SUM(package_rows), 0) AS packages
                FROM scan_runs
                """
            ).fetchone()
        limits = {
            "scan_runs": analytics_max_events(),
            "findings": analytics_max_findings(),
            "packages": analytics_max_packages(),
        }
        counts = {
            "scan_runs": int(row["scan_runs"]),
            "findings": int(row["findings"]),
            "packages": int(row["packages"]),
        }
        return {
            "db_path": str(self.db_path),
            "bytes": self._storage_bytes(),
            **counts,
            "limits": limits,
            "over_limit": any(limits[key] > 0 and counts[key] > limits[key] for key in limits),
        }

    def prune(
        self,
        *,
        max_runs: int | None = None,
        max_packages: int | None = None,
        max_findings: int | None = None,
        apply: bool = False,
        compact: bool = False,
    ) -> dict[str, Any]:
        """Plan or apply whole-run retention, optionally compacting SQLite."""
        bytes_before = self._storage_bytes()
        with closing(self._connect()) as conn:
            stale = plan_local_scan_prune(
                conn,
                max_events=max_runs,
                max_packages=max_packages,
                max_findings=max_findings,
            )
            if apply and stale:
                conn.executemany("DELETE FROM scan_runs WHERE run_id = ?", ((run_id,) for run_id in stale))
                conn.commit()
            if apply and compact:
                conn.execute("VACUUM")
        return {
            "db_path": str(self.db_path),
            "applied": apply,
            "compacted": bool(apply and compact),
            "deleted_runs": len(stale),
            "bytes_before": bytes_before,
            "bytes_after": self._storage_bytes(),
        }

    def _storage_bytes(self) -> int:
        return sum(
            path.stat().st_size for path in (self.db_path, Path(f"{self.db_path}-wal"), Path(f"{self.db_path}-shm")) if path.exists()
        )

    def query(self, sql: str, params: Iterable[Any] = ()) -> list[dict[str, Any]]:
        """Run a read query against the local analytics store."""
        if not sql.lstrip().lower().startswith("select"):
            raise ValueError("local analytics queries are read-only")
        with closing(self._connect()) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]


def record_scan_report_best_effort(
    report_json: dict[str, Any],
    *,
    source: str,
    tenant_id: str = "default",
    artifact_path: str | Path | None = None,
    db_path: str | Path | None = None,
) -> str | None:
    """Record a scan locally without allowing analytics to break scan output."""
    try:
        return LocalAnalyticsStore(db_path).record_scan_report(
            report_json,
            source=source,
            tenant_id=tenant_id,
            artifact_path=artifact_path,
        )
    except Exception:
        return None


def _iter_findings(report_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    findings = report_json.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, dict):
                yield item
        return

    blast_radius = report_json.get("blast_radius") or report_json.get("blast_radii") or []
    if isinstance(blast_radius, list):
        for item in blast_radius:
            if isinstance(item, dict):
                yield item


def _iter_packages(report_json: dict[str, Any]) -> Iterable[dict[str, Any]]:
    agents = report_json.get("agents") or []
    if not isinstance(agents, list):
        return
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        agent_name = str(agent.get("name") or "")
        servers = agent.get("mcp_servers") or []
        if not isinstance(servers, list):
            continue
        for server in servers:
            if not isinstance(server, dict):
                continue
            server_name = str(server.get("name") or "")
            packages = server.get("packages") or []
            if not isinstance(packages, list):
                continue
            for package in packages:
                if isinstance(package, dict):
                    yield {
                        "agent_name": agent_name,
                        "server_name": server_name,
                        **package,
                    }


_OCCURRENCE_FIELDS = (
    "occurrence_id",
    "occurrence_key",
    "finding_id",
    "source_finding_id",
    "path",
    "file",
    "file_path",
    "manifest_path",
    "config_path",
    "location",
    "locations",
    "source_location",
    "line",
    "line_number",
    "start_line",
    "column",
    "column_number",
    "start_column",
    "rule",
    "rule_id",
    "check_id",
    "control_id",
    "resource_id",
    "resource_arn",
)


def _finding_rows(run_id: str, scan_id: str, findings: list[dict[str, Any]]) -> list[tuple[Any, ...]]:
    """Build deterministic occurrence rows without changing canonical identity.

    ``finding_key`` is the SQLite row boundary. A unique semantic finding keeps
    its existing key for compatibility. When one semantic key has multiple
    occurrences, each stored row gets a deterministic occurrence suffix; exact
    duplicate producer rows collapse instead of aborting the transaction.
    """
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    projections_by_semantic: dict[str, set[str]] = defaultdict(set)
    for finding in findings:
        vulnerability_id = _vulnerability_id_from_finding(finding)
        package_ref = str(finding.get("package") or "")
        ecosystem = str(finding.get("ecosystem") or "")
        semantic_key = _finding_key(finding, vulnerability_id, package_ref, ecosystem)
        occurrence_key = _finding_occurrence_key(finding, package_ref, ecosystem)
        projection_key = _finding_projection_key(finding)
        storage_discriminator = f"{occurrence_key}:{projection_key}"
        entries.setdefault((semantic_key, storage_discriminator), finding)
        projections_by_semantic[semantic_key].add(storage_discriminator)

    rows: list[tuple[Any, ...]] = []
    for (semantic_key, storage_discriminator), finding in entries.items():
        if len(projections_by_semantic[semantic_key]) == 1:
            storage_key = semantic_key
        else:
            suffix = uuid.uuid5(uuid.NAMESPACE_URL, f"agent-bom:local-finding-occurrence:{storage_discriminator}")
            storage_key = f"{semantic_key}:{suffix}"
        rows.append(_finding_row(run_id, scan_id, finding, finding_key=storage_key))
    return rows


def _finding_occurrence_key(finding: dict[str, Any], package_ref: str, ecosystem: str) -> str:
    raw_asset = finding.get("asset")
    asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    raw_evidence = finding.get("evidence")
    evidence: dict[str, Any] = raw_evidence if isinstance(raw_evidence, dict) else {}
    occurrence = {
        "explicit": {key: finding.get(key) for key in _OCCURRENCE_FIELDS if finding.get(key) not in (None, "", [], {})},
        "asset": {
            key: asset.get(key)
            for key in (
                "canonical_id",
                "stable_id",
                "asset_type",
                "identifier",
                "location",
                "name",
                "provider",
                "account_ref",
                "region",
                "environment",
            )
            if asset.get(key) not in (None, "", [], {})
        },
        "evidence": {key: evidence.get(key) for key in _OCCURRENCE_FIELDS if evidence.get(key) not in (None, "", [], {})},
        "affected_agents": sorted(str(item) for item in finding.get("affected_agents") or []),
        "affected_servers": sorted(str(item) for item in finding.get("affected_servers") or []),
        "package": package_ref,
        "ecosystem": ecosystem,
    }
    return json.dumps(occurrence, sort_keys=True, separators=(",", ":"), default=str)


def _finding_projection_key(finding: dict[str, Any]) -> str:
    """Return a stable full-row key so only structurally exact duplicates collapse."""
    canonical = json.dumps(finding, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _finding_row(
    run_id: str,
    scan_id: str,
    finding: dict[str, Any],
    *,
    finding_key: str | None = None,
) -> tuple[Any, ...]:
    raw_asset = finding.get("asset")
    asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
    vulnerability_id = _vulnerability_id_from_finding(finding)
    package_ref = str(finding.get("package") or "")
    package_name = str(finding.get("package_name") or _package_name_from_ref(package_ref))
    package_version = str(finding.get("package_version") or _package_version_from_ref(package_ref))
    ecosystem = str(finding.get("ecosystem") or "")
    storage_key = finding_key or _finding_key(finding, vulnerability_id, package_ref, ecosystem)
    return (
        run_id,
        scan_id,
        storage_key,
        vulnerability_id,
        package_name,
        package_version,
        package_ref,
        ecosystem,
        _finding_severity(finding),
        _float(finding.get("risk_score")),
        str(finding.get("schema_version") or ""),
        str(finding.get("finding_type") or ""),
        str(finding.get("source") or ""),
        str(finding.get("title") or ""),
        json.dumps(asset, sort_keys=True),
        json.dumps(finding, sort_keys=True, default=str),
        str(finding.get("canonical_id") or ""),
        str(asset.get("canonical_id") or ""),
        json.dumps(list(finding.get("affected_agents") or []), sort_keys=True),
        json.dumps(list(finding.get("affected_servers") or []), sort_keys=True),
    )


def _package_row(run_id: str, scan_id: str, package: dict[str, Any]) -> tuple[Any, ...]:
    package_name = str(package.get("name") or "")
    package_version = str(package.get("version") or "")
    ecosystem = str(package.get("ecosystem") or "")
    purl = package.get("purl")
    return (
        run_id,
        scan_id,
        str(package.get("agent_name") or ""),
        str(package.get("server_name") or ""),
        package_name,
        package_version,
        ecosystem,
        purl,
        str(package.get("canonical_id") or canonical_package_id(package_name, package_version, ecosystem, str(purl or "") or None)),
    )


def _run_id(report_json: dict[str, Any]) -> str:
    scan_run = report_json.get("scan_run")
    if isinstance(scan_run, dict):
        raw = str(scan_run.get("run_id") or "").strip()
        if raw:
            return raw
    return f"local-run-{uuid.uuid4()}"


def _finding_key(finding: dict[str, Any], vulnerability_id: str, package_ref: str, ecosystem: str) -> str:
    raw = str(finding.get("id") or finding.get("stable_id") or "").strip()
    if raw:
        return raw
    parts = [
        vulnerability_id,
        package_ref,
        ecosystem,
        str(finding.get("finding_type") or ""),
        str(finding.get("source") or ""),
        str(finding.get("title") or ""),
    ]
    joined = "|".join(part for part in parts if part)
    return joined or str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(finding, sort_keys=True, default=str)))


def _vulnerability_id_from_finding(finding: dict[str, Any]) -> str:
    raw = str(finding.get("vulnerability_id") or finding.get("cve_id") or "").strip()
    if raw:
        return raw
    raw_id = str(finding.get("id") or "").strip()
    upper_id = raw_id.upper()
    if upper_id.startswith(("CVE-", "GHSA-", "DEBIAN-CVE-", "ALAS-", "RUSTSEC-")):
        return raw_id
    return ""


def _finding_severity(finding: dict[str, Any]) -> str:
    return str(finding.get("effective_severity") or finding.get("severity") or "unknown").lower()


def _package_name_from_ref(package_ref: str) -> str:
    if "@" not in package_ref:
        return package_ref
    return package_ref.rsplit("@", 1)[0]


def _package_version_from_ref(package_ref: str) -> str:
    if "@" not in package_ref:
        return ""
    return package_ref.rsplit("@", 1)[1]


def _int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _float(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)).fetchone()
    return row is not None


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
