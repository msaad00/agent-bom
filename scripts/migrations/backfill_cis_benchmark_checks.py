#!/usr/bin/env python3
"""Backfill normalized CIS benchmark check rows from scan_jobs JSONB.

The migration is idempotent: each scan_id/team_id slice is deleted and rebuilt
from the scan result blob. It is intended for existing Postgres deployments
that already have CIS benchmark data stored in scan_jobs.data.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

from agent_bom.analytics_contract import build_cis_benchmark_check_rows


def _connect(url: str):
    try:
        import psycopg
    except ImportError as exc:  # pragma: no cover - exercised only without postgres extra
        raise SystemExit("Install the postgres extra first: pip install 'agent-bom[postgres]'") from exc
    return psycopg.connect(url)


def _job_result(raw: Any) -> dict[str, Any] | None:
    data = raw if isinstance(raw, dict) else json.loads(raw)
    result = data.get("result")
    return result if isinstance(result, dict) else None


def backfill(url: str) -> int:
    written = 0
    with _connect(url) as conn:
        rows = conn.execute("SELECT job_id, team_id, created_at, completed_at, data FROM scan_jobs").fetchall()
        for job_id, team_id, created_at, completed_at, data in rows:
            result = _job_result(data)
            if not result:
                continue
            checks = build_cis_benchmark_check_rows(result, str(job_id), measured_at=completed_at or created_at)
            conn.execute("DELETE FROM cis_benchmark_checks WHERE scan_id = %s AND team_id = %s", (job_id, team_id))
            for check in checks:
                conn.execute(
                    """INSERT INTO cis_benchmark_checks (
                           scan_id, team_id, cloud, check_id, title, status, severity, cis_section, evidence,
                           resource_ids, remediation, fix_cli, fix_console, effort, priority, guardrails,
                           requires_human_review, measured_at
                       ) VALUES (
                           %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s::jsonb, %s, %s, %s, %s, %s, %s, %s
                       )""",
                    (
                        job_id,
                        team_id,
                        check["cloud"],
                        check["check_id"],
                        check["title"],
                        check["status"],
                        check["severity"],
                        check["cis_section"],
                        check["evidence"],
                        json.dumps(check["resource_ids"]),
                        json.dumps(check["remediation"], sort_keys=True),
                        check["fix_cli"],
                        check["fix_console"],
                        check["effort"],
                        int(check["priority"]),
                        check["guardrails"],
                        bool(check["requires_human_review"]),
                        check["measured_at"] or completed_at or created_at,
                    ),
                )
                written += 1
        conn.commit()
    return written


def main() -> int:
    url = os.environ.get("AGENT_BOM_POSTGRES_URL", "").strip()
    if not url:
        print("AGENT_BOM_POSTGRES_URL is required", file=sys.stderr)
        return 2
    count = backfill(url)
    print(f"Backfilled {count} CIS benchmark check row(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
