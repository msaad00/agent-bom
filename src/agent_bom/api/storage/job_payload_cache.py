"""Byte-bounded reuse of serialized job payloads for one exact committed row version.

A job's ``data`` column can be tens of megabytes. Reads send the version tokens
this process already holds, and the database returns the payload only for rows
whose current version differs, so a stale payload can never be served. Only the
immutable JSON text is shared across requests; a parsed ``ScanJob`` is shared
at most within one aggregate read scope (see ``parse_job_payload``).
"""

from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Any

from agent_bom.api.storage.jobs import parse_job_payload
from agent_bom.config import _int

DEFAULT_MAX_BYTES = _int("AGENT_BOM_POSTGRES_JOB_PAYLOAD_CACHE_MB", 256) * 1024 * 1024
TOKEN_SEPARATOR = "\x1f"
_VERSION = "concat_ws(chr(31), team_id, job_id, xmin::text, pg_column_size(data)::text)"


class JobPayloadCache:
    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self._max_bytes = max(0, max_bytes)
        self._entries: OrderedDict[str, tuple[str, str, int]] = OrderedDict()
        self._bytes = 0
        self._lock = threading.Lock()
        self.fetched = 0

    def get(self, token: str) -> str | None:
        with self._lock:
            entry = self._entries.get(token)
            if entry is None:
                return None
            self._entries.move_to_end(token)
            return entry[1]

    def tokens(self, tenant_id: str | None) -> list[str]:
        with self._lock:
            return [token for token, (tenant, _, _) in self._entries.items() if tenant_id is None or tenant == tenant_id]

    def put(self, tenant_id: str, token: str, payload: str) -> None:
        size = len(payload.encode("utf-8"))
        with self._lock:
            self.fetched += 1
            if self._max_bytes == 0 or size > self._max_bytes:
                return
            previous = self._entries.pop(token, None)
            if previous is not None:
                self._bytes -= previous[2]
            self._entries[token] = (tenant_id, payload, size)
            self._bytes += size
            while self._bytes > self._max_bytes:
                _, (_, _, evicted_size) = self._entries.popitem(last=False)
                self._bytes -= evicted_size

    def forget(self, tenant_id: str, job_id: str) -> None:
        prefix = f"{tenant_id}{TOKEN_SEPARATOR}{job_id}{TOKEN_SEPARATOR}"
        with self._lock:
            for token in [token for token in self._entries if token.startswith(prefix)]:
                self._bytes -= self._entries.pop(token)[2]


def read_versioned_jobs(conn: Any, cache: JobPayloadCache, where: str, params: tuple, tenant_id: str | None, suffix: str) -> list[Any]:
    """Parse each ``scan_jobs`` row, transferring only payload versions the cache does not hold."""
    rows = conn.execute(
        f"SELECT team_id, {_VERSION}, CASE WHEN {_VERSION} = ANY(%s::text[]) THEN NULL ELSE data::text END "  # nosec B608
        f"FROM scan_jobs{where} {suffix}",
        (cache.tokens(tenant_id), *params),
    ).fetchall()
    jobs = []
    for team_id, version, payload in rows:
        if payload is not None:
            cache.put(team_id, version, payload)
        elif (payload := cache.get(version)) is None:
            # Evicted after the token snapshot; read this row's current payload directly.
            team, job_id, _ = version.split(TOKEN_SEPARATOR, 2)
            row = conn.execute("SELECT data::text FROM scan_jobs WHERE team_id = %s AND job_id = %s", (team, job_id)).fetchone()
            if row is None:
                continue
            payload = row[0]
        jobs.append(parse_job_payload(payload))
    return jobs
