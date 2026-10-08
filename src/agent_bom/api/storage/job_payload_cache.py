"""Byte-bounded reuse of serialized job payloads for one exact committed row version.

A job's ``data`` column can be tens of megabytes. Reads send the version tokens
this process already holds, and the database returns the payload only for rows
whose current version differs, so a stale payload can never be served. Callers
always parse a fresh ``ScanJob``; only the immutable JSON text is shared.
"""

from __future__ import annotations

import threading
from collections import OrderedDict

from agent_bom.config import _int

DEFAULT_MAX_BYTES = _int("AGENT_BOM_POSTGRES_JOB_PAYLOAD_CACHE_MB", 256) * 1024 * 1024
TOKEN_SEPARATOR = "\x1f"


class JobPayloadCache:
    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self._max_bytes = max(0, max_bytes)
        self._entries: OrderedDict[str, tuple[str, str]] = OrderedDict()
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
            return [token for token, (tenant, _) in self._entries.items() if tenant_id is None or tenant == tenant_id]

    def put(self, tenant_id: str, token: str, payload: str) -> None:
        size = len(payload)
        with self._lock:
            self.fetched += 1
            if size > self._max_bytes:
                return
            previous = self._entries.pop(token, None)
            if previous is not None:
                self._bytes -= len(previous[1])
            self._entries[token] = (tenant_id, payload)
            self._bytes += size
            while self._bytes > self._max_bytes:
                _, (_, evicted) = self._entries.popitem(last=False)
                self._bytes -= len(evicted)

    def forget(self, tenant_id: str, job_id: str) -> None:
        prefix = f"{tenant_id}{TOKEN_SEPARATOR}{job_id}{TOKEN_SEPARATOR}"
        with self._lock:
            for token in [token for token in self._entries if token.startswith(prefix)]:
                self._bytes -= len(self._entries.pop(token)[1])
