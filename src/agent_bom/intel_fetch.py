"""Governed threat-intel raw artifact fetch helpers.

This module is intentionally narrow: it fetches allowlisted structured sources
from the canonical intel source registry, records provenance, and leaves
parsing/redistribution to higher-level connectors.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from agent_bom.http_client import create_client, request_with_retry
from agent_bom.intel_lookup import IntelSource

_ALLOWED_CONTENT_TYPES = (
    "application/json",
    "application/xml",
    "application/stix+json",
    "application/taxii+json",
    "application/gzip",
    "application/x-gzip",
    "text/csv",
    "text/plain",
    "text/xml",
)
_FETCHABLE_CONNECTORS = {
    "structured_api",
    "bulk_file",
    "bulk_json",
    "csaf_json",
    "vendor_json_seed",
}


class GovernedIntelFetchError(ValueError):
    """Raised when a source cannot be fetched under the governed policy."""


@dataclass(frozen=True)
class GovernedRawArtifact:
    """Fetched raw source bytes plus provenance required for later parsing."""

    source_id: str
    source_url: str
    fetched_at: str
    content_type: str
    size_bytes: int
    content_hash: str
    etag: str | None
    last_modified: str | None
    parser_version: str
    license: str
    license_or_terms_url: str
    robots_policy: str
    body: bytes

    def metadata(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "source_url": self.source_url,
            "fetched_at": self.fetched_at,
            "content_type": self.content_type,
            "size_bytes": self.size_bytes,
            "content_hash": self.content_hash,
            "etag": self.etag,
            "last_modified": self.last_modified,
            "parser_version": self.parser_version,
            "license": self.license,
            "license_or_terms_url": self.license_or_terms_url,
            "robots_policy": self.robots_policy,
        }


def ensure_source_fetch_allowed(source: IntelSource) -> None:
    """Validate source registry metadata before any network fetch."""

    if not source.enabled:
        raise GovernedIntelFetchError(f"{source.source_id} is disabled")
    if source.connector_type not in _FETCHABLE_CONNECTORS:
        raise GovernedIntelFetchError(f"{source.source_id} connector {source.connector_type!r} is not fetchable")
    if source.robots_policy in {"manual_seed_only", "manual_only"}:
        raise GovernedIntelFetchError(f"{source.source_id} is marked manual-only")
    if not source.license_or_terms_url or not source.license:
        raise GovernedIntelFetchError(f"{source.source_id} is missing license or terms metadata")


def _content_type_allowed(content_type: str) -> bool:
    normalized = content_type.split(";", 1)[0].strip().lower()
    return any(normalized == allowed for allowed in _ALLOWED_CONTENT_TYPES)


async def fetch_governed_raw_artifact(
    source: IntelSource,
    *,
    max_bytes: int = 1_000_000,
    timeout: float = 15.0,
) -> GovernedRawArtifact:
    """Fetch one canonical source under the governed intel policy."""

    ensure_source_fetch_allowed(source)
    async with create_client(timeout=timeout) as client:
        response = await request_with_retry(client, "GET", source.source_url, max_retries=1)
    if response is None:
        raise GovernedIntelFetchError(f"{source.source_id} fetch did not return a response")
    if response.status_code >= 400:
        raise GovernedIntelFetchError(f"{source.source_id} fetch returned HTTP {response.status_code}")
    content_type = response.headers.get("content-type", "application/octet-stream")
    if not _content_type_allowed(content_type):
        raise GovernedIntelFetchError(f"{source.source_id} returned unsupported content type {content_type!r}")
    body = response.content
    if len(body) > max_bytes:
        raise GovernedIntelFetchError(f"{source.source_id} response exceeded {max_bytes} bytes")
    digest = hashlib.sha256(body).hexdigest()
    return GovernedRawArtifact(
        source_id=source.source_id,
        source_url=source.source_url,
        fetched_at=datetime.now(UTC).isoformat(),
        content_type=content_type,
        size_bytes=len(body),
        content_hash=f"sha256:{digest}",
        etag=response.headers.get("etag"),
        last_modified=response.headers.get("last-modified"),
        parser_version=source.parser_version,
        license=source.license,
        license_or_terms_url=source.license_or_terms_url,
        robots_policy=source.robots_policy,
        body=body,
    )


def store_raw_artifact(artifact: GovernedRawArtifact, root: Path) -> dict[str, Any]:
    """Persist raw bytes separately from derived intel records."""

    digest = artifact.content_hash.removeprefix("sha256:")
    source_dir = root / artifact.source_id
    source_dir.mkdir(parents=True, exist_ok=True)
    body_path = source_dir / f"{digest}.raw"
    metadata_path = source_dir / f"{digest}.metadata.json"
    body_path.write_bytes(artifact.body)
    metadata = artifact.metadata() | {"body_path": str(body_path)}
    metadata_path.write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return metadata | {"metadata_path": str(metadata_path)}
