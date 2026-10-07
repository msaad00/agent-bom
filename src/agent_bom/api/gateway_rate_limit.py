"""Gateway rate-limit backend selection and readiness diagnostics."""

from __future__ import annotations

import logging
import os

from agent_bom.agent_identity import ANONYMOUS
from agent_bom.api.gateway_request import _sanitize_for_log
from agent_bom.api.middleware import InMemoryRateLimitStore, PostgresRateLimitStore
from agent_bom.api.storage_schema import postgres_deployment_configured
from agent_bom.runtime.gateway_settings import GatewaySettings

logger = logging.getLogger("agent_bom.gateway_server")


def _gateway_configured_replicas() -> int:
    raw = os.environ.get("AGENT_BOM_GATEWAY_REPLICAS", "").strip()
    if not raw:
        return 1
    try:
        return max(1, int(raw))
    except ValueError:
        logger.warning("Invalid AGENT_BOM_GATEWAY_REPLICAS=%r; defaulting to 1", _sanitize_for_log(raw))
        return 1


def _gateway_shared_rate_limit_required(settings: GatewaySettings) -> bool:
    if settings.require_shared_rate_limit:
        return True
    return _gateway_configured_replicas() > 1


def _build_gateway_rate_limit_store(settings: GatewaySettings):
    if settings.runtime_rate_limit_per_tenant_per_minute <= 0:
        return None
    if postgres_deployment_configured():
        try:
            return PostgresRateLimitStore(window_seconds=60)
        except Exception as exc:
            raise RuntimeError(
                "Configured Postgres gateway rate limiter could not initialize; refusing to fall back to process-local state"
            ) from exc
    if _gateway_shared_rate_limit_required(settings):
        raise RuntimeError(
            "Shared gateway rate limiting is required for multi-replica or fail-closed deployments. "
            "Configure AGENT_BOM_POSTGRES_URL before starting the gateway."
        )
    return InMemoryRateLimitStore(window_seconds=60)


def _gateway_rate_limit_runtime_status(settings: GatewaySettings) -> dict[str, object]:
    postgres_configured = postgres_deployment_configured()
    replicas = _gateway_configured_replicas()
    enabled = settings.runtime_rate_limit_per_tenant_per_minute > 0
    shared_required = _gateway_shared_rate_limit_required(settings) if enabled else False
    backend = "disabled" if not enabled else ("postgres_shared" if postgres_configured else "inmemory_single_process")
    return {
        "enabled": enabled,
        "limit_per_tenant_per_minute": settings.runtime_rate_limit_per_tenant_per_minute,
        "backend": backend,
        "postgres_configured": postgres_configured,
        "configured_gateway_replicas": replicas,
        "shared_required": shared_required,
        "shared_across_replicas": enabled and postgres_configured,
        "fail_closed": (enabled and postgres_configured) or (enabled and shared_required),
        "message": (
            "Gateway runtime rate limiting disabled."
            if not enabled
            else (
                "Gateway runtime rate limiting uses Postgres-backed per-source-agent state across replicas."
                if postgres_configured
                else (
                    "Gateway runtime rate limiting is per-source-agent and process-local because the gateway "
                    "is configured for a single replica. Multi-replica deployments must configure AGENT_BOM_POSTGRES_URL."
                )
            )
        ),
    }


def _rate_limit_bucket_component(value: str) -> str:
    component = _sanitize_for_log(value).strip() or ANONYMOUS
    return component.replace(":", "_")[:160]
