"""Example third-party runtime emitter plugin registration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.plugin_entrypoints import RuntimeEmitterPluginRegistration

_BUFFER: list[dict[str, Any]] = []


def registration() -> RuntimeEmitterPluginRegistration:
    """Return a metadata registration for a redacted runtime event sink."""

    return RuntimeEmitterPluginRegistration(
        name="example-runtime-emitter",
        module="example_runtime_emitter",
        emit_attr="emit",
        flush_attr="flush",
        capabilities=ExtensionCapabilities(
            scan_modes=("runtime_event_emit",),
            required_scopes=("runtime_event_write",),
            outbound_destinations=("telemetry.internal",),
            data_boundary="redacted_runtime_metadata",
            network_access=True,
            writes=True,
            guarantees=("operator_enabled", "redacted_payloads", "no_prompt_bodies"),
        ),
        source="example",
    )


def emit(event: dict[str, Any]) -> dict[str, Any]:
    """Buffer a redacted runtime event envelope.

    The example keeps only routing metadata and explicitly avoids raw prompts,
    arguments, and credential values.
    """

    envelope = {
        "schema_version": "example.runtime_event.v1",
        "received_at": datetime.now(UTC).isoformat(),
        "tenant_id": str(event.get("tenant_id") or "default"),
        "source_agent": str(event.get("source_agent") or "anonymous"),
        "tool": str(event.get("tool") or ""),
        "decision": str(event.get("decision") or "observed"),
    }
    _BUFFER.append(envelope)
    return {"queued": True, "buffered": len(_BUFFER)}


def flush() -> dict[str, Any]:
    """Flush buffered event envelopes."""

    flushed = len(_BUFFER)
    _BUFFER.clear()
    return {"flushed": flushed}
