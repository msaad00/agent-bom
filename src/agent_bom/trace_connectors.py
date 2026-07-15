"""Native trace-pull connectors for LLM-observability platforms.

Teams already sending agent traces to an LLM-observability platform should not
have to re-wire an OTLP exporter to get agent-bom correlation. These connectors
*pull* traces from Langfuse and LangSmith via their REST APIs and adapt them
into the flat OTLP span shape that :mod:`agent_bom.otel_ingest` already parses —
so the same parse + span-identity correlation + (opt-in) content screening
pipeline runs regardless of how the trace arrived.

Design:
- The OTel span parsing in ``otel_ingest`` is reused; only the API clients are
  new. Each connector maps its native records to ``{"spans": [ ...OTLP... ]}``.
- Credentials (Langfuse public/secret key, LangSmith API key) are passed in by
  the caller from the secret store / request body. They are used for auth only
  and are **never logged**.
- The HTTP client is injectable (``client=``) so tests exercise the mapping with
  mocked HTTP and no network.
- Metadata (tool name, server, package) is always mapped. Free-text content
  (tool output / model completion) is mapped **only** when ``include_content``
  is set, mirroring the opt-in, privacy-safe content posture of the ingest path.
"""

from __future__ import annotations

import logging
from typing import Any, Protocol, cast

logger = logging.getLogger(__name__)

LANGFUSE = "langfuse"
LANGSMITH = "langsmith"

_DEFAULT_LIMIT = 50
_MAX_LIMIT = 1000
_HTTP_TIMEOUT = 20.0


class TraceConnectorError(RuntimeError):
    """Raised when a trace connector cannot authenticate or reach its API."""


class _HttpResponse(Protocol):
    status_code: int

    def json(self) -> Any: ...


class _HttpClient(Protocol):
    def request(self, method: str, url: str, **kwargs: Any) -> _HttpResponse: ...


def list_trace_connectors() -> list[dict[str, Any]]:
    """Describe the available native trace-pull connectors."""
    return [
        {
            "name": LANGFUSE,
            "kind": "llm_observability",
            "auth_fields": ["host", "public_key", "secret_key"],
            "supports_content": True,
        },
        {
            "name": LANGSMITH,
            "kind": "llm_observability",
            "auth_fields": ["api_key", "api_url", "project"],
            "supports_content": True,
        },
    ]


def _bounded_limit(limit: int) -> int:
    return max(1, min(int(limit or _DEFAULT_LIMIT), _MAX_LIMIT))


def _attr(key: str, value: Any) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": "" if value is None else str(value)}}


def _client_or_default(client: _HttpClient | None) -> tuple[_HttpClient, bool]:
    if client is not None:
        return client, False
    import httpx

    return cast("_HttpClient", httpx.Client(timeout=_HTTP_TIMEOUT)), True


def _call_json(client: _HttpClient, method: str, url: str, **kwargs: Any) -> Any:
    try:
        resp = client.request(method, url, timeout=_HTTP_TIMEOUT, **kwargs)
    except Exception as exc:  # noqa: BLE001 — surface a clean, credential-free error
        raise TraceConnectorError(f"trace connector request failed: {type(exc).__name__}") from exc
    status = getattr(resp, "status_code", 0)
    if status >= 400:
        raise TraceConnectorError(f"trace connector returned HTTP {status}")
    return resp.json()


# ─── Langfuse ──────────────────────────────────────────────────────────────


def _langfuse_observation_to_span(obs: dict[str, Any], *, include_content: bool) -> dict[str, Any] | None:
    if not isinstance(obs, dict):
        return None
    name = str(obs.get("name") or "").strip()
    if not name:
        return None
    attributes: list[dict[str, Any]] = [_attr("tool.name", name)]
    raw_meta = obs.get("metadata")
    metadata: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    server = metadata.get("server") or metadata.get("mcp_server") or obs.get("model")
    if server:
        attributes.append(_attr("mcp.server", server))
    package = metadata.get("package") or metadata.get("dependency")
    if package:
        attributes.append(_attr("package.name", package))
    if include_content and obs.get("output") is not None:
        attributes.append(_attr("tool.output", obs.get("output")))
    return {
        "traceId": str(obs.get("traceId") or obs.get("trace_id") or ""),
        "spanId": str(obs.get("id") or ""),
        "name": f"adk.tool.{name}",
        "attributes": attributes,
    }


def fetch_langfuse_traces(
    *,
    host: str,
    public_key: str,
    secret_key: str,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Pull recent Langfuse observations and adapt them to flat OTLP spans.

    ``public_key`` / ``secret_key`` are used for HTTP Basic auth only and are
    never logged. Returns ``{"spans": [...]}`` for ``otel_ingest`` to parse.
    """
    if not host or not public_key or not secret_key:
        raise TraceConnectorError("langfuse connector requires host, public_key and secret_key")
    base = host.rstrip("/")
    url = f"{base}/api/public/observations"
    resolved, owns = _client_or_default(client)
    try:
        payload = _call_json(
            resolved,
            "GET",
            url,
            params={"limit": _bounded_limit(limit)},
            auth=(public_key, secret_key),
        )
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()
    records = payload.get("data", []) if isinstance(payload, dict) else payload
    spans: list[dict[str, Any]] = []
    for obs in records or []:
        span = _langfuse_observation_to_span(obs, include_content=include_content)
        if span is not None:
            spans.append(span)
    logger.info("langfuse trace pull: %d spans", len(spans))
    return {"spans": spans}


# ─── LangSmith ─────────────────────────────────────────────────────────────


def _langsmith_run_to_span(run: dict[str, Any], *, include_content: bool) -> dict[str, Any] | None:
    if not isinstance(run, dict):
        return None
    name = str(run.get("name") or "").strip()
    if not name:
        return None
    attributes: list[dict[str, Any]] = [_attr("tool.name", name)]
    raw_extra = run.get("extra")
    extra: dict[str, Any] = raw_extra if isinstance(raw_extra, dict) else {}
    raw_meta = extra.get("metadata")
    metadata: dict[str, Any] = raw_meta if isinstance(raw_meta, dict) else {}
    server = metadata.get("server") or metadata.get("mcp_server")
    if server:
        attributes.append(_attr("mcp.server", server))
    package = metadata.get("package") or metadata.get("dependency")
    if package:
        attributes.append(_attr("package.name", package))
    if include_content and run.get("outputs") is not None:
        attributes.append(_attr("tool.output", run.get("outputs")))
    return {
        "traceId": str(run.get("trace_id") or run.get("session_id") or ""),
        "spanId": str(run.get("id") or ""),
        "name": f"adk.tool.{name}",
        "attributes": attributes,
    }


def fetch_langsmith_traces(
    *,
    api_key: str,
    api_url: str = "https://api.smith.langchain.com",
    project: str | None = None,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Pull recent LangSmith tool runs and adapt them to flat OTLP spans.

    ``api_key`` is sent as the ``x-api-key`` header only and is never logged.
    Returns ``{"spans": [...]}`` for ``otel_ingest`` to parse.
    """
    if not api_key:
        raise TraceConnectorError("langsmith connector requires api_key")
    base = (api_url or "https://api.smith.langchain.com").rstrip("/")
    body: dict[str, Any] = {"limit": _bounded_limit(limit), "run_type": "tool"}
    if project:
        body["project_name"] = project
    resolved, owns = _client_or_default(client)
    try:
        payload = _call_json(
            resolved,
            "POST",
            f"{base}/runs/query",
            headers={"x-api-key": api_key},
            json=body,
        )
    finally:
        if owns:
            getattr(resolved, "close", lambda: None)()
    records = payload.get("runs", []) if isinstance(payload, dict) else payload
    spans: list[dict[str, Any]] = []
    for run in records or []:
        span = _langsmith_run_to_span(run, include_content=include_content)
        if span is not None:
            spans.append(span)
    logger.info("langsmith trace pull: %d spans", len(spans))
    return {"spans": spans}


def fetch_traces(
    provider: str,
    credentials: dict[str, Any],
    *,
    limit: int = _DEFAULT_LIMIT,
    include_content: bool = False,
    client: _HttpClient | None = None,
) -> dict[str, Any]:
    """Dispatch a trace pull to the named provider.

    ``credentials`` carries the provider's auth fields (see
    :func:`list_trace_connectors`). Values are used for auth only and never
    logged. Returns flat OTLP ``{"spans": [...]}``.
    """
    key = (provider or "").strip().lower()
    if key == LANGFUSE:
        return fetch_langfuse_traces(
            host=str(credentials.get("host", "")),
            public_key=str(credentials.get("public_key", "")),
            secret_key=str(credentials.get("secret_key", "")),
            limit=limit,
            include_content=include_content,
            client=client,
        )
    if key == LANGSMITH:
        return fetch_langsmith_traces(
            api_key=str(credentials.get("api_key", "")),
            api_url=str(credentials.get("api_url", "") or "https://api.smith.langchain.com"),
            project=(str(credentials.get("project")) if credentials.get("project") else None),
            limit=limit,
            include_content=include_content,
            client=client,
        )
    raise TraceConnectorError(f"unknown trace connector '{provider}'")


__all__ = [
    "LANGFUSE",
    "LANGSMITH",
    "TraceConnectorError",
    "fetch_langfuse_traces",
    "fetch_langsmith_traces",
    "fetch_traces",
    "list_trace_connectors",
]
