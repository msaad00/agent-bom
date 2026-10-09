"""Serve the dashboard's ``/_next`` build assets without worker-thread hops.

Starlette's ``StaticFiles`` stats every request on a worker thread and streams
the body through more thread hops. Those threads compete for the GIL and the
AnyIO limiter with the dashboard's CPU-bound aggregate reads, so a 50 KB
chunk waited seconds while a page loaded. The build output is immutable for
the life of the process, so each file is read once and then answered from
memory on the event loop. Path resolution, ``ETag`` and ``Last-Modified`` are
Starlette's own; Range, HEAD, misses and oversize files fall back to it.
"""

from __future__ import annotations

import hashlib
import os
import stat
import threading
from dataclasses import dataclass
from email.utils import formatdate
from mimetypes import guess_type
from typing import Any

import anyio.to_thread
from starlette.datastructures import Headers
from starlette.responses import Response
from starlette.staticfiles import NotModifiedResponse, StaticFiles

MAX_CACHED_FILE_BYTES = 4 * 1024 * 1024
MAX_CACHED_TOTAL_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class _Asset:
    body: bytes
    media_type: str
    etag: str
    last_modified: str


class InMemoryBuildAssets(StaticFiles):
    """``StaticFiles`` that answers repeat requests from an in-memory copy."""

    def __init__(self, *, directory: str) -> None:
        super().__init__(directory=directory)
        self._assets: dict[str, _Asset] = {}
        self._cached_bytes = 0
        self._lock = threading.Lock()

    async def get_response(self, path: str, scope: Any) -> Response:
        request_headers = Headers(scope=scope)
        if scope["method"] != "GET" or "range" in request_headers:
            return await super().get_response(path, scope)
        asset = self._assets.get(path)
        if asset is None:
            asset = await anyio.to_thread.run_sync(self._load, path)
            if asset is None:
                return await super().get_response(path, scope)
        response = Response(
            asset.body,
            media_type=asset.media_type,
            headers={"etag": asset.etag, "last-modified": asset.last_modified},
        )
        if self.is_not_modified(response.headers, request_headers):
            return NotModifiedResponse(response.headers)
        return response

    def _load(self, path: str) -> _Asset | None:
        full_path, stat_result = self.lookup_path(path)
        if stat_result is None or not stat.S_ISREG(stat_result.st_mode) or stat_result.st_size > MAX_CACHED_FILE_BYTES:
            return None
        with open(full_path, "rb") as handle:
            body = handle.read()
        if len(body) != stat_result.st_size:
            return None
        etag_base = f"{stat_result.st_mtime}-{stat_result.st_size}"
        asset = _Asset(
            body=body,
            media_type=guess_type(os.path.basename(full_path))[0] or "text/plain",
            etag=f'"{hashlib.md5(etag_base.encode(), usedforsecurity=False).hexdigest()}"',
            last_modified=formatdate(stat_result.st_mtime, usegmt=True),
        )
        with self._lock:
            if path not in self._assets and self._cached_bytes + len(body) <= MAX_CACHED_TOTAL_BYTES:
                self._assets[path] = asset
                self._cached_bytes += len(body)
        return asset
