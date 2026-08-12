"""Threat-intel MCP tool implementations."""

from __future__ import annotations

import ipaddress
import json
import logging
import os
from typing import Any
from urllib.parse import urlsplit

from agent_bom import __version__
from agent_bom.http_client import create_client, request_with_retry
from agent_bom.intel_lookup import build_daily_brief, list_intel_sources, lookup_advisory, match_packages
from agent_bom.mcp_errors import (
    CODE_INTERNAL_UNEXPECTED,
    CODE_UPSTREAM_UNAVAILABLE,
    CODE_VALIDATION_INVALID_ARGUMENT,
    CODE_VALIDATION_MISSING_REQUIRED,
    mcp_error_json,
)
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)

_YDC_BASE_URL = "https://ydc-index.io"
_YDC_ALLOWED_HOSTS = frozenset({"ydc-index.io", "api.ydc-index.io"})


def _resolve_youcom_base_url(raw: str | None) -> str:
    """Return a base URL safe to send ``YDC_API_KEY`` to.

    The request carries the caller's API key, so the host it goes to is not a
    free parameter. An override is honoured only when it stays on a You.com
    origin over TLS, or points at loopback — the same posture
    ``ai_enrich._url_is_loopback`` takes for ``OPENAI_API_BASE``, and the one
    ``cloud/azure_graph.py`` takes for credentialed Graph pagination.
    """
    if not raw or not raw.strip():
        return _YDC_BASE_URL

    candidate = raw.strip().rstrip("/")
    parsed = urlsplit(candidate)
    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not hostname:
        raise ValueError("YOUCOM_BASE_URL must be an http(s) URL")

    is_loopback = hostname == "localhost" or hostname.endswith(".localhost")
    if not is_loopback:
        try:
            is_loopback = ipaddress.ip_address(hostname).is_loopback
        except ValueError:
            is_loopback = False

    if is_loopback:
        return candidate

    if parsed.scheme != "https":
        raise ValueError("YOUCOM_BASE_URL must use https for a non-loopback host")
    if hostname not in _YDC_ALLOWED_HOSTS and not hostname.endswith(".ydc-index.io"):
        raise ValueError(f"refusing to send YDC_API_KEY off-origin to {hostname}")
    return candidate


def _youcom_result_summary(result: dict[str, Any]) -> dict[str, Any]:
    """Return a compact, stable view of a You.com search result."""
    snippets = result.get("snippets") or []
    if not isinstance(snippets, list):
        snippets = [snippets]

    summary = {
        "title": result.get("title", ""),
        "url": result.get("url", ""),
        "description": result.get("description", ""),
        "snippets": [str(snippet) for snippet in snippets if snippet][:3],
        "page_age": result.get("page_age", ""),
        "favicon_url": result.get("favicon_url", ""),
        "thumbnail_url": result.get("thumbnail_url", ""),
    }

    contents = result.get("contents")
    if isinstance(contents, dict):
        summary["contents"] = {key: contents[key] for key in ("markdown", "html") if contents.get(key)}

    return summary


async def intel_lookup_impl(*, advisory_id: str, _truncate_response=lambda value: value) -> str:
    """Look up one CVE/GHSA/OSV advisory from local intel."""

    try:
        advisory = (advisory_id or "").strip()
        if not advisory:
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "advisory_id is required", details={"argument": "advisory_id"})
        result = lookup_advisory(advisory)
        # Opt-in operator advisory source plugins augment the local record with
        # provenance-tagged metadata (off by default; see plugin_activation).
        from agent_bom.plugin_activation import advisory_source_lookup

        operator_sources = advisory_source_lookup(advisory)
        if operator_sources and isinstance(result, dict):
            result = {**result, "operator_advisory_sources": operator_sources}
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "advisory_id"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel lookup failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel lookup failed.", details={"error": sanitize_error(exc)})


async def intel_match_impl(
    *,
    packages: list[dict] | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    name: str | None = None,
    version: str | None = None,
    limit: int = 100,
    _truncate_response=lambda value: value,
) -> str:
    """Match package inventory coordinates to local advisory intel."""

    try:
        submitted = list(packages or [])
        if purl or ecosystem or name:
            submitted.append({"purl": purl or "", "ecosystem": ecosystem or "", "name": name or "", "version": version or ""})
        if not submitted:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "Provide packages or a single purl/ecosystem/name package.",
                details={"argument": "packages"},
            )
        return _truncate_response(json.dumps(match_packages(submitted, limit=limit), indent=2, default=str))
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "packages"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel match failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel match failed.", details={"error": sanitize_error(exc)})


async def intel_sources_impl(*, _truncate_response=lambda value: value) -> str:
    """Return canonical threat-intel source and feed-run metadata."""

    try:
        return _truncate_response(json.dumps(list_intel_sources(), indent=2, default=str))
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel sources failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel sources failed.", details={"error": sanitize_error(exc)})


async def intel_daily_brief_impl(
    *,
    packages: list[dict] | None = None,
    telemetry_indicators: list[dict] | None = None,
    campaign_activity: list[dict] | None = None,
    ransomware_claims: list[dict] | None = None,
    tenant_profile: dict | None = None,
    epss_threshold: float = 0.7,
    kev_window_hours: int = 24,
    limit: int = 100,
    _truncate_response=lambda value: value,
) -> str:
    """Return a local analyst threat brief from governed intel sources."""

    try:
        return _truncate_response(
            json.dumps(
                build_daily_brief(
                    packages or [],
                    telemetry_indicators=telemetry_indicators or [],
                    campaign_activity=campaign_activity or [],
                    ransomware_claims=ransomware_claims or [],
                    tenant_profile=tenant_profile or {},
                    epss_threshold=epss_threshold,
                    kev_window_hours=kev_window_hours,
                    limit=limit,
                ),
                indent=2,
                default=str,
            )
        )
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "daily_brief"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel daily brief failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel daily brief failed.", details={"error": sanitize_error(exc)})


async def youcom_search_impl(
    *,
    query: str,
    count: int = 10,
    freshness: str | None = None,
    country: str | None = None,
    language: str | None = None,
    safesearch: str | None = None,
    livecrawl: str | None = None,
    crawl_timeout: int = 10,
    _truncate_response=lambda value: value,
) -> str:
    """Search You.com for current web or news context."""

    try:
        q = (query or "").strip()
        if not q:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "query is required",
                details={"argument": "query"},
            )

        api_key = (os.environ.get("YDC_API_KEY") or "").strip()
        if not api_key:
            return mcp_error_json(
                CODE_VALIDATION_MISSING_REQUIRED,
                "YDC_API_KEY is required for You.com search.",
                details={"environment_variable": "YDC_API_KEY"},
            )

        base_url = _resolve_youcom_base_url(os.environ.get("YOUCOM_BASE_URL"))
        params: dict[str, Any] = {
            "query": q,
            "count": max(1, min(int(count or 10), 100)),
        }
        if freshness:
            params["freshness"] = freshness.strip()
        if country:
            params["country"] = country.strip().upper()
        if language:
            params["language"] = language.strip()
        if safesearch:
            params["safesearch"] = safesearch.strip()
        if livecrawl:
            params["livecrawl"] = livecrawl.strip()
        if crawl_timeout:
            params["crawl_timeout"] = max(1, min(int(crawl_timeout), 60))

        async with create_client(timeout=20.0) as client:
            response = await request_with_retry(
                client,
                "GET",
                f"{base_url}/v1/search",
                headers={
                    "X-API-Key": api_key,
                    "User-Agent": f"agent-bom/{__version__} youdotcom-integration/agent-bom",
                },
                params=params,
            )

        if response is None:
            return mcp_error_json(
                CODE_UPSTREAM_UNAVAILABLE,
                "You.com search request failed.",
                details={"upstream": "youcom_search", "reason": "request_exhausted"},
            )

        if response.status_code != 200:
            return mcp_error_json(
                CODE_UPSTREAM_UNAVAILABLE,
                "You.com search returned an error.",
                details={
                    "upstream": "youcom_search",
                    "status_code": response.status_code,
                    # Redacted before it reaches an MCP client: an upstream body
                    # can echo the request, and the request carries the API key.
                    "response": sanitize_error((response.text or "")[:500]),
                },
            )

        payload = response.json()
        results = payload.get("results") if isinstance(payload, dict) else {}
        # `or []` rather than a bare .get: You.com omits a section entirely when
        # it has no hits, and iterating that None would surface as an internal
        # error rather than an empty result set.
        web_results = (results.get("web") or []) if isinstance(results, dict) else []
        news_results = (results.get("news") or []) if isinstance(results, dict) else []
        metadata = payload.get("metadata") if isinstance(payload, dict) else {}

        compact = {
            "schema_version": "youcom.search.v1",
            "query": q,
            "metadata": {
                "search_uuid": metadata.get("search_uuid", "") if isinstance(metadata, dict) else "",
                "latency": metadata.get("latency", None) if isinstance(metadata, dict) else None,
                "count": params["count"],
                "freshness": params.get("freshness"),
                "country": params.get("country"),
                "language": params.get("language"),
                "safesearch": params.get("safesearch"),
                "livecrawl": params.get("livecrawl"),
                "crawl_timeout": params.get("crawl_timeout"),
                "base_url": base_url,
            },
            "results": {
                "web": [_youcom_result_summary(item) for item in web_results if isinstance(item, dict)],
                "news": [_youcom_result_summary(item) for item in news_results if isinstance(item, dict)],
            },
        }
        return _truncate_response(json.dumps(compact, indent=2, default=str))
    except ValueError as exc:
        return mcp_error_json(
            CODE_VALIDATION_INVALID_ARGUMENT,
            sanitize_error(exc),
            details={"argument": "youcom_search"},
        )
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP You.com search failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "You.com search failed.", details={"error": sanitize_error(exc)})
