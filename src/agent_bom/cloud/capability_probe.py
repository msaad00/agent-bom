"""Bounded, read-only provider capability verification.

Credential material being present or successfully brokered is not proof that a
provider can serve the inventory surfaces agent-bom advertises.  This module is
the shared CLI/API boundary that proves one least-privilege read per provider
without returning provider identities or raw SDK errors.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType
from typing import Any

_PROVIDER_CALL_TIMEOUT_SECONDS = 10.0

PROBE_NOT_RUN = "not_run"
PROBE_VERIFIED = "verified"
PROBE_INVALID_CREDENTIALS = "invalid_credentials"
PROBE_PERMISSION_DENIED = "permission_denied"
PROBE_TIMEOUT = "timeout"
PROBE_INVALID_CONFIGURATION = "invalid_configuration"
PROBE_UNAVAILABLE = "unavailable"

_FAILURE_DETAILS = {
    PROBE_INVALID_CREDENTIALS: "Cloud capability probe could not authenticate. Verify the configured credential.",
    PROBE_PERMISSION_DENIED: "Cloud capability probe was denied. Verify the provider read permissions.",
    PROBE_TIMEOUT: "Cloud capability probe timed out. Verify the provider endpoint and network path.",
    PROBE_INVALID_CONFIGURATION: "Cloud capability probe is missing required non-secret provider configuration.",
    PROBE_UNAVAILABLE: "Cloud capability probe failed. Verify provider availability and configuration.",
}


@dataclass(frozen=True)
class CapabilityProbeResult:
    """Successful, non-secret capability receipt."""

    capabilities: tuple[str, ...]


class CapabilityProbeError(RuntimeError):
    """Probe failure carrying only a stable public code."""

    def __init__(self, code: str) -> None:
        self.code = code if code in _FAILURE_DETAILS else PROBE_UNAVAILABLE
        super().__init__(self.code)


def _load_vertex_module() -> ModuleType:
    from google.cloud import aiplatform_v1  # type: ignore

    return aiplatform_v1


def classify_probe_failure(exc: BaseException) -> str:
    """Map SDK/network failures to a stable code without inspecting messages."""
    if isinstance(exc, CapabilityProbeError):
        return exc.code
    if isinstance(exc, TimeoutError):
        return PROBE_TIMEOUT

    name = type(exc).__name__.lower()
    if any(token in name for token in ("timeout", "deadlineexceeded")):
        return PROBE_TIMEOUT
    if any(token in name for token in ("accessdenied", "permissiondenied", "forbidden", "unauthorized")):
        return PROBE_PERMISSION_DENIED
    if any(token in name for token in ("nocredentials", "invalidcredential", "unauthenticated", "refresherror")):
        return PROBE_INVALID_CREDENTIALS
    return PROBE_UNAVAILABLE


def probe_failure_detail(code: str) -> str:
    """Return fixed operator guidance for a public probe code."""
    return _FAILURE_DETAILS.get(code, _FAILURE_DETAILS[PROBE_UNAVAILABLE])


def scan_verified_capabilities(provider: str) -> tuple[str, ...]:
    """Capabilities necessarily exercised by a successful full provider scan."""
    return {
        "aws": ("bedrock:list-agents", "aws:inventory", "aws:cis-read"),
        "gcp": ("vertex-ai:list-endpoints", "gcp:inventory", "gcp:cis-read"),
        "azure": ("azure:inventory", "azure:cis-read"),
        "snowflake": ("snowflake:inventory",),
    }.get(provider, ("cloud:inventory",))


def _probe_aws(brokered: object) -> CapabilityProbeResult:
    client = brokered.client("bedrock-agent")  # type: ignore[attr-defined]
    client.list_agents(maxResults=1)
    return CapabilityProbeResult(("bedrock:list-agents",))


def _probe_gcp(
    brokered: object,
    *,
    regions: list[str],
    auth_params: dict[str, Any],
) -> CapabilityProbeResult:
    project_id = str(auth_params.get("project_id") or "").strip()
    if not project_id:
        raise CapabilityProbeError(PROBE_INVALID_CONFIGURATION)
    region = next((str(item).strip() for item in regions if str(item).strip()), "us-central1")
    client = _load_vertex_module().EndpointServiceClient(credentials=brokered)
    endpoints = client.list_endpoints(
        request={"parent": f"projects/{project_id}/locations/{region}", "page_size": 1},
        timeout=_PROVIDER_CALL_TIMEOUT_SECONDS,
    )
    # Request only one item and advance at most once so pagination cannot turn a
    # readiness check into inventory work.
    next(iter(endpoints), None)
    return CapabilityProbeResult(("vertex-ai:list-endpoints",))


def _probe_azure(brokered: object) -> CapabilityProbeResult:
    brokered.get_token("https://management.azure.com/.default")  # type: ignore[attr-defined]
    return CapabilityProbeResult(("azure-management:token",))


def _probe_snowflake(brokered: object) -> CapabilityProbeResult:
    try:
        cursor = brokered.cursor()  # type: ignore[attr-defined]
        cursor.execute("SELECT CURRENT_VERSION()")
        cursor.fetchone()
    finally:
        try:
            brokered.close()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 - close is best-effort after read probe
            pass
    return CapabilityProbeResult(("snowflake:select-current-version",))


def probe_read_capability(
    provider: str,
    brokered: object,
    *,
    regions: list[str],
    auth_params: dict[str, Any],
) -> CapabilityProbeResult:
    """Prove one provider-specific read and return a non-secret receipt."""
    try:
        if provider == "aws":
            return _probe_aws(brokered)
        if provider == "gcp":
            return _probe_gcp(brokered, regions=regions, auth_params=auth_params)
        if provider == "azure":
            return _probe_azure(brokered)
        if provider == "snowflake":
            return _probe_snowflake(brokered)
        raise CapabilityProbeError(PROBE_INVALID_CONFIGURATION)
    except CapabilityProbeError:
        raise
    except Exception as exc:  # noqa: BLE001 - SDK errors cross a stable boundary
        raise CapabilityProbeError(classify_probe_failure(exc)) from exc
