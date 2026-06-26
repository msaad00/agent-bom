"""Cloud scanning REST routes — estate inventory + CIS benchmark over HTTP.

Cloud discovery has long been reachable from the CLI (``agent-bom cloud …``) and
over MCP (``cloud_inventory`` / ``cis_benchmark`` tools), but not over REST. That
left API-only / SaaS consumers unable to reach cloud scanning at all. These
endpoints close the surface-parity gap by calling the **same** cloud inventory and
CIS benchmark functions the CLI and MCP already use, returning a deterministic
result shape that matches them field-for-field.

Endpoints:
    GET /v1/cloud/{provider}/inventory       estate asset inventory summary
    GET /v1/cloud/{provider}/cis-benchmark   CIS Foundations benchmark report

``provider`` is one of ``aws`` | ``azure`` | ``gcp``; ``all`` is also accepted for
inventory (estate-wide fan-out). Every endpoint enforces the same tenant + role
gate the sibling routes use: ``require_request_tenant_id`` plus the ``scan``
permission ({admin, analyst}) via the shared RBAC dependency, so there is no
unauthenticated cloud scan and an under-privileged role is rejected with 403.

Responses are additive: where the underlying scan carries a read-only discovery
envelope (``permissions_used`` / discovery scope), it is surfaced under
``audit_metadata`` so auditors can verify the read-only scope used.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["cloud"])
_logger = logging.getLogger(__name__)

# Reuse the same RBAC gate the sibling scan/identity routes use. Cloud scanning is
# a scan-class action, so it maps to the "scan" permission ({admin, analyst}).
_SCAN_DEP = require_authenticated_permission("scan")

_INVENTORY_PROVIDERS = ("aws", "azure", "gcp")
_CIS_PROVIDERS = ("aws", "azure", "gcp")
_REGION_RE = re.compile(r"[a-z]{2}(-gov)?-[a-z]+-\d{1,2}")
_PROFILE_RE = re.compile(r"[a-zA-Z0-9._-]{1,100}")
# Audit-field allowlists. IAM action identifiers (AWS ``svc:Action``, GCP
# ``svc.resource.verb``, Azure ``Provider/type/op``), discovery scopes (account
# IDs, regions, project IDs, ARNs), and the discovery-mode/redaction enums are
# all structured tokens with no whitespace or punctuation that could carry a
# stack trace or CRLF. Matching against these patterns is the sanitizer barrier
# that keeps any exception-derived text in a provider payload out of the REST
# response, independent of where the value originated.
_PERMISSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/*-]{0,200}")
_SCOPE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/*-]{0,300}")
_AUDIT_ENUM_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,40}")


def _clean_tokens(values: Any, pattern: re.Pattern[str], *, cap: int = 500) -> list[str]:
    """Keep only well-formed, structured tokens — the sanitizer barrier.

    Each value is coerced, stripped, and admitted only if it fully matches the
    allowlist ``pattern``. Anything carrying whitespace, control characters, or
    free-form prose (i.e. an exception/stack fragment) is dropped, so no
    exception-derived text can reach the response even if it appears in a
    provider payload field.
    """
    cleaned: list[str] = []
    for value in values or []:
        token = str(value).strip()
        if token and pattern.fullmatch(token):
            cleaned.append(token)
        if len(cleaned) >= cap:
            break
    return cleaned


def _tenant(request: Request) -> str:
    return require_request_tenant_id(request)


def _redact_summary(summary: dict[str, Any]) -> dict[str, Any]:
    """Strip exception-derived free-form warnings from the external REST response.

    Provider discovery warnings are built from caught exceptions
    (``sanitize_discovery_warning(exc)``), so surfacing them verbatim over REST
    risks exposing backend detail. Keep the ``warnings`` key (REST/MCP shape
    parity) but replace its value with a count-derived, exception-free notice;
    the full warnings remain available via the CLI/MCP surfaces and the server log.
    """
    safe = dict(summary)
    count = len(safe.get("warnings") or [])
    safe["warnings"] = [f"{count} provider discovery warning(s) — run via CLI/MCP or see server logs for detail."] if count else []
    return safe


def _audit_metadata(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    """Roll the per-provider read-only discovery envelopes into one audit block.

    Surfaces ``permissions_used`` and the discovery scope so an auditor can verify
    the read-only IAM footprint the scan actually used. Additive — the underlying
    payloads are untouched.
    """
    permissions: list[str] = []
    scopes: list[str] = []
    redaction: list[str] = []
    scan_modes: list[str] = []
    for payload in payloads:
        envelope = payload.get("discovery_envelope")
        if not isinstance(envelope, dict):
            continue
        permissions.extend(_clean_tokens(envelope.get("permissions_used"), _PERMISSION_RE))
        scopes.extend(_clean_tokens(envelope.get("discovery_scope"), _SCOPE_RE))
        redaction.extend(_clean_tokens([envelope.get("redaction_status")], _AUDIT_ENUM_RE))
        scan_modes.extend(_clean_tokens([envelope.get("scan_mode")], _AUDIT_ENUM_RE))
    return {
        "read_only": True,
        "writes_performed": False,
        "scan_modes": sorted(set(scan_modes)),
        "permissions_used": sorted(set(permissions)),
        "discovery_scope": sorted(set(scopes)),
        "redaction_status": sorted(set(redaction)),
        "note": (
            "agent-bom cloud scanning is read-only and agentless. permissions_used lists the exact "
            "read-only IAM actions exercised; no resource is mutated and no secret value is returned."
        ),
    }


@router.get("/v1/cloud/{provider}/inventory")
async def cloud_inventory(
    request: Request,
    provider: str,
    region: str = Query("", description="Optional region scope (AWS only, e.g. us-east-1)."),
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Estate-wide cloud asset inventory summary for a provider (or ``all``).

    Calls the same ``discover_inventory`` functions the CLI and MCP ``cloud_inventory``
    tool use and reduces each provider payload to the identical non-secret count
    shape (``_summarize_inventory_payload``). Each provider self-gates on its own
    ``AGENT_BOM_*_INVENTORY`` env flag + credentials; a disabled provider returns a
    clear ``status`` and contributes zero nodes.
    """
    tenant_id = _tenant(request)
    requested = provider.strip().lower()
    if requested == "all":
        selected = list(_INVENTORY_PROVIDERS)
    elif requested in _INVENTORY_PROVIDERS:
        selected = [requested]
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join((*_INVENTORY_PROVIDERS, 'all'))}.",
        )

    scoped_region = region.strip() or None
    if scoped_region and not _REGION_RE.fullmatch(scoped_region):
        raise HTTPException(status_code=400, detail=f"Invalid region format: {region}")

    try:
        from agent_bom.cloud import aws_inventory, azure_inventory, gcp_inventory
        from agent_bom.mcp_tools.posture import _summarize_inventory_payload

        raw_payloads: list[dict[str, Any]] = []
        summaries: list[dict[str, Any]] = []
        if "aws" in selected:
            payload = aws_inventory.discover_inventory(region=scoped_region)
            raw_payloads.append(payload)
            summaries.append(_summarize_inventory_payload("aws", payload))
        if "azure" in selected:
            payload = azure_inventory.discover_inventory()
            raw_payloads.append(payload)
            summaries.append(_summarize_inventory_payload("azure", payload))
        if "gcp" in selected:
            payload = gcp_inventory.discover_inventory()
            raw_payloads.append(payload)
            summaries.append(_summarize_inventory_payload("gcp", payload))

        any_enabled = any(s["status"] != "disabled" for s in summaries)
        return {
            "schema_version": "cloud.inventory.summary.v1",
            "tenant_id": tenant_id,
            "status": "ok" if any_enabled else "disabled",
            "total_resources": sum(s["resource_count"] for s in summaries),
            "total_identities": sum(s["identity_count"] for s in summaries),
            "providers": [_redact_summary(s) for s in summaries],
            "audit_metadata": _audit_metadata(raw_payloads),
            "note": (
                "Estate-wide inventory is opt-in per provider via AGENT_BOM_CLOUD_INVENTORY / "
                "AGENT_BOM_AZURE_INVENTORY / AGENT_BOM_GCP_INVENTORY. Reference-only counts; "
                "no resource secrets are returned."
            ),
        }
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Full diagnostics go to the server log only; the client gets a generic
        # message so no exception/stack detail is exposed over REST.
        _logger.exception("Cloud inventory failed")
        raise HTTPException(status_code=500, detail="Cloud inventory failed; see server logs.") from exc


@router.get("/v1/cloud/{provider}/cis-benchmark")
async def cloud_cis_benchmark(
    request: Request,
    provider: str,
    checks: str = Query("", description="Optional comma-separated CIS check ids to scope the run."),
    region: str = Query("", description="Optional AWS region (e.g. us-east-1)."),
    profile: str = Query("", description="Optional AWS profile name."),
    subscription_id: str = Query("", description="Optional Azure subscription id."),
    project_id: str = Query("", description="Optional GCP project id."),
    _role: Any = _SCAN_DEP,
) -> dict[str, Any]:
    """Run the CIS Foundations benchmark for a cloud provider over REST.

    Calls the same provider ``run_benchmark`` functions the CLI and MCP
    ``cis_benchmark`` tool use and returns the report's canonical ``to_dict()``
    shape unchanged, so REST / CLI / MCP report the same checks and counts.
    """
    tenant_id = _tenant(request)
    requested = provider.strip().lower()
    if requested not in _CIS_PROVIDERS:
        raise HTTPException(
            status_code=404,
            detail=f"Unsupported provider '{provider}'. Use one of: {', '.join(_CIS_PROVIDERS)}.",
        )

    check_list = [c.strip() for c in checks.split(",") if c.strip()] or None
    region_arg = region.strip() or None
    profile_arg = profile.strip() or None
    if region_arg and not _REGION_RE.fullmatch(region_arg):
        raise HTTPException(status_code=400, detail=f"Invalid AWS region format: {region}")
    if profile_arg and not _PROFILE_RE.fullmatch(profile_arg):
        raise HTTPException(
            status_code=400,
            detail="Invalid AWS profile name. Use alphanumeric, dot, dash, underscore (max 100 chars).",
        )

    try:
        from agent_bom.cloud import CloudDiscoveryError

        report: Any
        try:
            if requested == "aws":
                from agent_bom.cloud.aws_cis_benchmark import run_benchmark as run_aws_cis

                report = run_aws_cis(region=region_arg, profile=profile_arg, checks=check_list)
            elif requested == "azure":
                from agent_bom.cloud.azure_cis_benchmark import run_benchmark as run_azure_cis

                report = run_azure_cis(subscription_id=subscription_id.strip() or None, checks=check_list)
            else:  # gcp
                from agent_bom.cloud.gcp_cis_benchmark import run_benchmark as run_gcp_cis

                report = run_gcp_cis(project_id=project_id.strip() or None, checks=check_list)
        except CloudDiscoveryError:
            # Provider SDK absent / credentials unavailable degrades to a clear
            # error envelope (HTTP 200) — exactly as the MCP cis_benchmark tool
            # does — never a 500. Keeps REST / MCP shape parity for the no-SDK path.
            # Log only a canonical allowlisted provider label — a literal chosen by
            # comparison, never the user string or the exception (avoids log injection
            # + exception-detail exposure; CR/LF strip alone isn't a recognized barrier).
            if requested == "aws":
                provider_label = "aws"
            elif requested == "azure":
                provider_label = "azure"
            elif requested == "gcp":
                provider_label = "gcp"
            else:
                provider_label = "unknown"
            _logger.warning("Cloud CIS benchmark unavailable for %s", provider_label)
            return {
                "error": "Provider SDK or credentials unavailable for this benchmark.",
                "provider": requested,
                "tenant_id": tenant_id,
                "status": "unavailable",
            }

        result = report.to_dict()
        result.setdefault("tenant_id", tenant_id)
        result["audit_metadata"] = {
            "read_only": True,
            "writes_performed": False,
            "provider": requested,
            "note": "CIS benchmark is read-only; checks evaluate posture without mutating any resource.",
        }
        return result
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        # Full diagnostics to the server log only; client gets a generic message.
        _logger.exception("Cloud CIS benchmark failed")
        raise HTTPException(status_code=500, detail="Cloud CIS benchmark failed; see server logs.") from exc
