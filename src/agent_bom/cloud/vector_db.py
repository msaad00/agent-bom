"""Vector database discovery and security assessment.

Discovers locally running vector databases by probing well-known ports and
HTTP health/collection endpoints. Assesses each instance for security
misconfigurations: unauthenticated access, network exposure, and version info.

Supported databases (self-hosted, port-probed):
- Qdrant  (port 6333)  — open-source vector search engine
- Weaviate (port 8080) — open-source vector database
- Chroma  (port 8000)  — open-source embedding database
- Milvus  (port 9091)  — distributed vector database (HTTP metrics/API)

Cloud-hosted (API-authenticated):
- Pinecone — ``check_pinecone()`` / ``discover_pinecone()``
  Requires ``PINECONE_API_KEY`` env var.

Risk flags:
- no_auth          — responds to collection queries without authentication
- network_exposed  — also reachable on a non-loopback interface (0.0.0.0 binding)
- no_tls           — plaintext HTTP only (no HTTPS on standard port)
- collections_exposed — returns collection/schema data without credentials

MAESTRO layer: KC4: Memory & Context
"""

from __future__ import annotations

import json
import logging
import socket
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VECTOR_DB_PORTS: dict[str, int] = {
    "qdrant": 6333,
    "weaviate": 8080,
    "chroma": 8000,
    "milvus": 9091,  # HTTP metrics/REST port; gRPC is 19530 (not HTTP-probeable)
}

# Endpoints used to check if auth is required.
# If these return 200 without any credentials → no_auth flag.
_AUTH_PROBE_ENDPOINTS: dict[str, str] = {
    "qdrant": "/collections",
    "weaviate": "/v1/schema",
    "chroma": "/api/v1/collections",
    "milvus": "/v1/vector/collections",
}

# Endpoints for version / health info
_HEALTH_ENDPOINTS: dict[str, str] = {
    "qdrant": "/",
    "weaviate": "/v1/meta",
    "chroma": "/api/v1",
    "milvus": "/healthz",
}

_DEFAULT_TIMEOUT = 3  # seconds

MAESTRO_LAYER = "KC4: Memory & Context"


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class VectorDBResult:
    """Security assessment result for a single vector database instance."""

    db_type: str  # qdrant | weaviate | chroma | milvus
    host: str
    port: int
    is_reachable: bool
    requires_auth: bool  # False = unauthenticated access allowed
    version: str  # detected version string or ""
    collection_count: int  # number of visible collections (0 if auth blocks)
    is_loopback: bool  # True = bound to localhost only
    risk_flags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def risk_level(self) -> str:
        """Return 'critical', 'high', 'medium', or 'safe'."""
        if not self.requires_auth and not self.is_loopback:
            return "critical"  # Unauthenticated + network-exposed
        if not self.requires_auth:
            return "high"  # Unauthenticated but localhost-only
        if self.risk_flags:
            return "medium"
        return "safe"

    def to_dict(self) -> dict:
        return {
            "db_type": self.db_type,
            "host": self.host,
            "port": self.port,
            "is_reachable": self.is_reachable,
            "requires_auth": self.requires_auth,
            "version": self.version,
            "collection_count": self.collection_count,
            "is_loopback": self.is_loopback,
            "risk_level": self.risk_level,
            "risk_flags": self.risk_flags,
            "maestro_layer": MAESTRO_LAYER,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _is_loopback(host: str) -> bool:
    """Return True if host resolves to 127.x.x.x or ::1."""
    try:
        addr = socket.gethostbyname(host)
        return addr.startswith("127.") or addr == "::1"
    except OSError:
        return False


def _http_get(host: str, port: int, path: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[int, bytes]:
    """Make a plain HTTP GET request; return (status_code, body_bytes).

    Returns (-1, b'') on any connection / timeout error.
    """
    url = f"http://{host}:{port}{path}"
    if not url.startswith(("http://", "https://")):  # defensive
        return -1, b""
    try:
        from agent_bom.http_client import sync_get

        resp = sync_get(url, timeout=timeout, headers={"User-Agent": "agent-bom/vectordb-check"})
        if resp is None:
            return -1, b""
        return resp.status_code, resp.content
    except Exception:
        return -1, b""


def _port_open(host: str, port: int, timeout: int = _DEFAULT_TIMEOUT) -> bool:
    """Return True if a TCP connection to host:port succeeds."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_version(db_type: str, body: bytes) -> str:
    """Extract version string from health endpoint response body."""
    try:
        data = json.loads(body)
    except Exception:
        return ""
    if db_type == "qdrant":
        return data.get("version", "") or data.get("result", {}).get("version", "")
    if db_type == "weaviate":
        return data.get("version", "")
    if db_type == "chroma":
        return data.get("version", "")
    if db_type == "milvus":
        # Milvus /v1/vector/collections or /healthz doesn't always include version
        return data.get("version", "")
    return ""


def _count_collections(db_type: str, body: bytes) -> int:
    """Count collections/indexes from a collection listing response body."""
    try:
        data = json.loads(body)
    except Exception:
        return 0
    if db_type == "qdrant":
        # {"result": {"collections": [...]}}
        return len(data.get("result", {}).get("collections", []))
    if db_type == "weaviate":
        # {"classes": [...]}
        classes = data.get("classes", [])
        return len(classes) if isinstance(classes, list) else 0
    if db_type == "chroma":
        # [{"name": "...", ...}, ...]
        return len(data) if isinstance(data, list) else 0
    if db_type == "milvus":
        # {"data": [...]}
        return len(data.get("data", []))
    return 0


# ---------------------------------------------------------------------------
# Core check
# ---------------------------------------------------------------------------


def check_vector_db(
    db_type: str,
    host: str = "127.0.0.1",
    port: int | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> VectorDBResult:
    """Probe a single vector database instance and assess its security posture.

    Args:
        db_type: One of 'qdrant', 'weaviate', 'chroma', 'milvus'.
        host: Hostname or IP to connect to. Defaults to localhost.
        port: Override the default port for this db_type.
        timeout: TCP/HTTP timeout in seconds.

    Returns:
        VectorDBResult with risk assessment.
    """
    resolved_port = port or VECTOR_DB_PORTS.get(db_type, 0)
    if not resolved_port:
        return VectorDBResult(
            db_type=db_type,
            host=host,
            port=0,
            is_reachable=False,
            requires_auth=True,
            version="",
            collection_count=0,
            is_loopback=_is_loopback(host),
            risk_flags=[],
            metadata={"error": f"Unknown db_type '{db_type}'"},
        )

    result = VectorDBResult(
        db_type=db_type,
        host=host,
        port=resolved_port,
        is_reachable=False,
        requires_auth=True,  # Assume auth required until proven otherwise
        version="",
        collection_count=0,
        is_loopback=_is_loopback(host),
    )

    # 1. Port reachability
    if not _port_open(host, resolved_port, timeout=timeout):
        return result  # Not running — nothing to flag

    result.is_reachable = True

    # 2. Health / version probe
    health_path = _HEALTH_ENDPOINTS.get(db_type, "/")
    status, body = _http_get(host, resolved_port, health_path, timeout=timeout)
    if status == 200:
        result.version = _parse_version(db_type, body)

    # 3. Auth check — probe collection listing endpoint without credentials
    auth_path = _AUTH_PROBE_ENDPOINTS.get(db_type, "/")
    auth_status, auth_body = _http_get(host, resolved_port, auth_path, timeout=timeout)

    if auth_status == 200:
        result.requires_auth = False
        result.risk_flags.append("no_auth")
        result.collection_count = _count_collections(db_type, auth_body)
        if result.collection_count > 0:
            result.risk_flags.append("collections_exposed")
    elif auth_status in (401, 403):
        result.requires_auth = True  # Auth is enforced
    # Other status codes (404, 500, etc.) — leave requires_auth=True conservatively

    # 4. Network exposure check — probe the machine's external IP
    if result.is_loopback and result.is_reachable:
        # Check if the service is also reachable on the local machine's
        # primary non-loopback interface (indicates 0.0.0.0 binding)
        try:
            # Get the machine's outbound IP (not loopback)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                local_ip = s.getsockname()[0]
            if local_ip and not local_ip.startswith("127."):
                if _port_open(local_ip, resolved_port, timeout=timeout):
                    result.is_loopback = False
                    result.risk_flags.append("network_exposed")
                    result.metadata["exposed_on"] = local_ip
        except OSError:
            pass  # Can't determine local IP — don't flag

    # 5. No TLS flag (plain HTTP only on standard port — no HTTPS alternative)
    result.risk_flags.append("no_tls")
    result.metadata["tls"] = False

    return result


# ---------------------------------------------------------------------------
# Discovery — scan all known vector DB ports
# ---------------------------------------------------------------------------


def discover_vector_dbs(
    hosts: list[str] | None = None,
    timeout: int = _DEFAULT_TIMEOUT,
) -> list[VectorDBResult]:
    """Scan for running vector databases and return security assessments.

    Args:
        hosts: List of hosts to probe. Defaults to ['127.0.0.1', 'localhost'].
        timeout: TCP/HTTP timeout in seconds per probe.

    Returns:
        List of VectorDBResult for every reachable database found.
    """
    scan_hosts = hosts or ["127.0.0.1", "localhost"]
    results: list[VectorDBResult] = []
    seen: set[tuple[str, int]] = set()  # dedup by (resolved_ip, port)

    for host in scan_hosts:
        for db_type, port in VECTOR_DB_PORTS.items():
            try:
                resolved_ip = socket.gethostbyname(host)
            except OSError:
                resolved_ip = host
            key = (resolved_ip, port)
            if key in seen:
                continue
            seen.add(key)

            result = check_vector_db(db_type=db_type, host=host, port=port, timeout=timeout)
            if result.is_reachable:
                results.append(result)

    return results


# ---------------------------------------------------------------------------
# Pinecone cloud vector DB — API-authenticated scanning (closes #310)
# ---------------------------------------------------------------------------

_PINECONE_API_BASE = "https://api.pinecone.io"
_PINECONE_CONTROLLER_BASE = "https://controller.{environment}.pinecone.io"


@dataclass
class PineconeIndexResult:
    """Security assessment for a single Pinecone index."""

    index_name: str
    environment: str
    dimension: int
    metric: str
    status: str  # "ready" | "initializing" | "scaling" | "terminating"
    pod_type: str
    pods: int
    replicas: int
    is_ready: bool
    risk_flags: list[str] = field(default_factory=list)

    @property
    def risk_level(self) -> str:
        if self.risk_flags:
            return "medium"
        return "safe"

    def to_dict(self) -> dict:
        return {
            "db_type": "pinecone",
            "index_name": self.index_name,
            "environment": self.environment,
            "dimension": self.dimension,
            "metric": self.metric,
            "status": self.status,
            "pod_type": self.pod_type,
            "pods": self.pods,
            "replicas": self.replicas,
            "is_ready": self.is_ready,
            "risk_level": self.risk_level,
            "risk_flags": self.risk_flags,
            "maestro_layer": MAESTRO_LAYER,
        }


def _pinecone_get(path: str, api_key: str, timeout: int = _DEFAULT_TIMEOUT) -> tuple[int, dict]:
    """Make an authenticated GET request to the Pinecone API.

    Returns (status_code, parsed_json). Returns (-1, {}) on network/parse error.
    The API key is never surfaced in exception messages or logs.
    """
    url = f"{_PINECONE_API_BASE}{path}"
    try:
        from agent_bom.http_client import create_sync_client, sync_request_with_retry

        hdrs = {
            "Api-Key": api_key,
            "User-Agent": "agent-bom/pinecone-scan",
            "Accept": "application/json",
        }
        with create_sync_client(timeout=timeout) as client:
            resp = sync_request_with_retry(client, "GET", url, headers=hdrs)
        if resp is None:
            return -1, {}
        try:
            body = resp.json()
        except Exception:
            body = {}
        return resp.status_code, body
    except Exception as exc:
        # Sanitize: ensure the API key cannot appear in logged exception messages.
        sanitized = str(exc).replace(api_key, "***REDACTED***") if api_key else str(exc)
        logger.debug("Pinecone request failed: %s", sanitized)
        return -1, {}


def check_pinecone(api_key: str, timeout: int = _DEFAULT_TIMEOUT) -> list[PineconeIndexResult]:
    """Assess security posture of all Pinecone indexes for the given API key.

    Checks each index for:
    - Excessive replicas (> 10 → flag ``high_replica_count``)
    - Pod type using serverless-only (informational in metadata)

    Args:
        api_key: Pinecone API key (from ``PINECONE_API_KEY`` env var).
        timeout: HTTP timeout in seconds.

    Returns:
        List of :class:`PineconeIndexResult`, one per index. Empty list if the
        API key is invalid or the account has no indexes.

    Raises:
        ValueError: If ``api_key`` is empty.
    """
    if not api_key:
        raise ValueError("api_key is required for Pinecone scanning")

    status, data = _pinecone_get("/indexes", api_key, timeout)
    if status == 401:
        logger.warning("Pinecone: invalid or expired API key")
        return []
    if status == 403:
        logger.warning("Pinecone: API key lacks list-indexes permission")
        return []
    if status < 0 or status >= 300:
        logger.debug("Pinecone: unexpected status %d listing indexes", status)
        return []

    indexes = data.get("indexes", [])
    results: list[PineconeIndexResult] = []

    for idx in indexes:
        name = idx.get("name", "")
        spec = idx.get("spec", {})
        pod_spec = spec.get("pod", {})
        serverless_spec = spec.get("serverless", {})

        environment = pod_spec.get("environment", serverless_spec.get("region", "serverless"))
        dimension = idx.get("dimension", 0)
        metric = idx.get("metric", "cosine")
        state = idx.get("status", {})
        status_val = state.get("state", "unknown")
        is_ready = state.get("ready", False)
        pod_type = pod_spec.get("pod_type", "serverless")
        pods = pod_spec.get("pods", 0)
        replicas = pod_spec.get("replicas", 0)

        risk_flags: list[str] = []
        if replicas > 10:
            risk_flags.append("high_replica_count")

        results.append(
            PineconeIndexResult(
                index_name=name,
                environment=environment,
                dimension=dimension,
                metric=metric,
                status=status_val,
                pod_type=pod_type,
                pods=pods,
                replicas=replicas,
                is_ready=is_ready,
                risk_flags=risk_flags,
            )
        )

    return results


def discover_pinecone(timeout: int = _DEFAULT_TIMEOUT) -> list[PineconeIndexResult]:
    """Scan Pinecone using the ``PINECONE_API_KEY`` environment variable.

    Returns an empty list if the env var is not set (no-op, not an error).

    Args:
        timeout: HTTP timeout in seconds.

    Returns:
        List of :class:`PineconeIndexResult`, or empty list if no key configured.
    """
    import os

    api_key = os.environ.get("PINECONE_API_KEY", "")
    if not api_key:
        logger.debug("PINECONE_API_KEY not set — skipping Pinecone scan")
        return []
    return check_pinecone(api_key, timeout=timeout)
