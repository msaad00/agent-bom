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
from typing import Any, cast
from urllib.parse import urlencode

import anyio.to_thread
from fastapi import APIRouter, HTTPException, Query, Request

from agent_bom.api.tenancy import require_request_tenant_id
from agent_bom.backpressure import BackpressureRejectedError, adaptive_backpressure
from agent_bom.rbac import require_authenticated_permission

router = APIRouter(tags=["cloud"])
_logger = logging.getLogger(__name__)

# Reuse the same RBAC gate the sibling scan/identity routes use. Cloud scanning is
# a scan-class action, so it maps to the "scan" permission ({admin, analyst}).
_SCAN_DEP = require_authenticated_permission("scan")
# The per-account drill summary is a read-only aggregation over already-ingested
# evidence — it never triggers a provider scan — so it maps to the "read" gate
# (all authenticated roles), like /v1/overview.
_READ_DEP = require_authenticated_permission("read")

# Bound the per-account read so one account view can never walk an unbounded
# number of rows on a huge tenant. Mirrors the intent of the findings-list
# backpressure guard; a sargable account-scoped GROUP BY in the hub store is a
# follow-up for million-row tenants (see PR notes).
_ACCOUNT_SUMMARY_MAX_ROWS = 50_000

# Asset-type buckets used to derive an honest identity/role count from the
# account's finding assets (deeper IAM/grant enumeration is a follow-up).
_IDENTITY_ASSET_TYPES = frozenset(
    {"user", "service_account", "identity", "iam_user", "principal", "machine_identity", "nhi"}
)
_ROLE_ASSET_TYPES = frozenset({"role", "iam_role", "cloud_role"})

# Provider -> the result keys (new + legacy) that carry a stored CIS benchmark
# side block. Matches the mapping the graph builder reads (#3946).
_CIS_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("aws", ("cis_benchmark", "cis_benchmark_data")),
    ("azure", ("azure_cis_benchmark", "azure_cis_benchmark_data")),
    ("gcp", ("gcp_cis_benchmark", "gcp_cis_benchmark_data")),
    ("snowflake", ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data")),
    ("databricks", ("databricks_cis_benchmark", "databricks_cis_benchmark_data")),
)

_INVENTORY_PROVIDERS = ("aws", "azure", "gcp")
_CIS_PROVIDERS = ("aws", "azure", "gcp", "snowflake")
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


@router.get("/cloud/{provider}/inventory")
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


@router.get("/cloud/{provider}/cis-benchmark")
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
            elif requested == "snowflake":
                from agent_bom.cloud.snowflake_cis_benchmark import run_benchmark as run_snowflake_cis

                # Snowflake has no region/profile/subscription/project scoping; its
                # account/user/authenticator come from the standard read-only env
                # credentials (SNOWFLAKE_ACCOUNT/USER + key-pair/SSO), mirroring how
                # the CLI/MCP snowflake CIS path resolves them. When the connector or
                # credentials are absent, run_benchmark raises CloudDiscoveryError and
                # the handler below degrades to the same HTTP-200 "unavailable" shape
                # as the other providers — never a 500.
                report = run_snowflake_cis(checks=check_list)
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
            elif requested == "snowflake":
                provider_label = "snowflake"
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


# ---------------------------------------------------------------------------
# Per-account drill summary (issue #3931)
#
# "Show me this cloud account end-to-end" — a single read-only aggregation over
# already-ingested findings + stored CIS benchmark blocks, scoped to one
# provider+account. It composes the exact rollup + scope filters #3946 shipped
# (never re-implements counting) and never triggers a live provider scan.
# ---------------------------------------------------------------------------


def _split_account_ref(raw: str | None) -> tuple[str, str, str]:
    """Return ``(canonical_ref, provider, bare_account)`` for a path param.

    Canonicalized (trimmed, provider lowercased) so ``AWS:1234`` and ``aws:1234``
    collapse. A value with no ``<provider>:<account>`` shape yields an empty
    provider/account so the endpoint returns an honest empty summary rather than
    raising — the same never-raise contract the #3946 scope filters hold.
    """
    text = (raw or "").strip()
    provider, sep, account = text.partition(":")
    provider = provider.strip().lower()
    account = account.strip()
    if not sep or not provider or not account:
        return "", "", ""
    return f"{provider}:{account}", provider, account


def _account_findings_href(account_ref: str, provider: str, *, domain: str | None = None) -> str:
    """Build a /findings deep-link pre-filtered to this account (and domain)."""
    params: dict[str, str] = {}
    if provider:
        params["provider"] = provider
    if account_ref:
        params["account"] = account_ref
    if domain:
        params["domain"] = domain
    query = urlencode(params)
    return f"/findings?{query}" if query else "/findings"


def _cis_block_account_id(data: dict[str, Any]) -> str:
    """Pull the account/subscription/project id out of a stored CIS block."""
    for key in ("account_id", "subscription_id", "aws_account_id", "project_id"):
        value = str(data.get(key) or "").strip()
        if value:
            return value
    return ""


def _cis_counts(data: dict[str, Any]) -> tuple[int, int]:
    """Return ``(passed, failed)`` for a CIS block, computing from checks if absent."""
    passed = data.get("passed")
    failed = data.get("failed")
    if isinstance(passed, int) and isinstance(failed, int):
        return passed, failed
    p = f = 0
    for check in data.get("checks", []) or []:
        if not isinstance(check, dict):
            continue
        status = str(check.get("status", "")).upper()
        if status == "PASS":
            p += 1
        elif status == "FAIL":
            f += 1
    return p, f


def _compliance_for_account(
    jobs_newest_first: list[Any], provider: str, wanted_ref: str
) -> dict[str, Any]:
    """Aggregate stored CIS pass-rate for the account (newest run per provider).

    Only blocks whose normalized account matches ``wanted_ref`` are counted; a
    block with no resolvable account id is admitted only when its provider equals
    the requested account's provider (the view is provider-scoped anyway), so a
    different account's run can never leak into this account's pass-rate. Honest
    empty (``pass_rate: null``) when no benchmark run exists for the account.
    """
    from agent_bom.finding_scope import normalize_account_ref

    benchmarks: list[dict[str, Any]] = []
    seen: set[str] = set()
    total_passed = total_failed = 0

    for job in jobs_newest_first:
        result = cast(dict[str, Any], getattr(job, "result", None) or {})
        for prov, keys in _CIS_SECTIONS:
            if provider and prov != provider:
                continue
            data: dict[str, Any] | None = None
            for key in keys:
                candidate = result.get(key)
                if isinstance(candidate, dict) and candidate:
                    data = candidate
                    break
            if data is None:
                continue
            block_provider = str(data.get("provider") or data.get("cloud_provider") or prov).strip().lower() or prov
            account_id = _cis_block_account_id(data)
            block_ref = normalize_account_ref(block_provider, account_id) if account_id else ""
            if block_ref:
                if block_ref.lower() != wanted_ref:
                    continue
            elif not provider or block_provider != provider:
                # No account id and no confident provider match — skip to stay honest.
                continue
            marker = f"{block_provider}:{block_ref or account_id or 'provider-scope'}"
            if marker in seen:
                continue  # newest run already recorded for this provider/account
            seen.add(marker)
            passed, failed = _cis_counts(data)
            evaluated = passed + failed
            total_passed += passed
            total_failed += failed
            benchmarks.append(
                {
                    "provider": block_provider,
                    "benchmark": str(data.get("benchmark") or "CIS"),
                    "passed": passed,
                    "failed": failed,
                    "evaluated": evaluated,
                    "pass_rate": round(passed / evaluated * 100, 1) if evaluated else None,
                }
            )

    evaluated = total_passed + total_failed
    return {
        "evaluated": evaluated,
        "passed": total_passed,
        "failed": total_failed,
        "pass_rate": round(total_passed / evaluated * 100, 1) if evaluated else None,
        "benchmarks": benchmarks,
    }


def _build_account_summary(tenant_id: str, raw_account_ref: str) -> dict[str, Any]:
    """Compose the per-account drill payload from stored evidence (sync body).

    Runs in a worker thread (see the route). Reuses the #3946 domain rollup
    buckets, the #3946 scope filters, and the shared scan-store helpers so no
    counting logic is re-implemented here.
    """
    from agent_bom.api.routes.overview import (
        _ALL_SEVERITY_KEYS,
        _COVERAGE_DOMAINS,
        _COVERAGE_LABELS,
        _bucket,
        _empty_severity,
        _row_domain,
    )
    from agent_bom.api.routes.scan import (
        _bulk_ingested_findings_for_tenant,
        _canonical_scope_filters,
        _completed_jobs_for_tenant,
        _finding_identity,
        _row_matches_scope,
    )

    canonical_ref, provider, account = _split_account_ref(raw_account_ref)

    lanes: dict[str, dict[str, int]] = {dom: _empty_severity() for dom in _COVERAGE_DOMAINS}
    counts: dict[str, int] = {dom: 0 for dom in _COVERAGE_DOMAINS}
    total_severity = _empty_severity()
    regions: set[str] = set()
    environments: set[str] = set()
    asset_ids: set[str] = set()
    identity_ids: set[str] = set()
    role_ids: set[str] = set()
    processed = 0
    truncated = False

    jobs = _completed_jobs_for_tenant(tenant_id)
    jobs_newest_first = sorted(
        jobs,
        key=lambda job: (getattr(job, "completed_at", "") or "", getattr(job, "created_at", "") or "", job.job_id),
        reverse=True,
    )

    if canonical_ref:
        # Dedupe findings across re-scans (latest occurrence of each id wins),
        # exactly like the findings-list default view, then fold bulk-ingested
        # rows in under the same identity so a finding seen twice counts once.
        filters = _canonical_scope_filters(None, canonical_ref, None, None)
        deduped: dict[str, dict[str, Any]] = {}
        for job in sorted(
            jobs,
            key=lambda job: (getattr(job, "completed_at", "") or "", getattr(job, "created_at", "") or "", job.job_id),
        ):
            for row in cast(dict[str, Any], getattr(job, "result", None) or {}).get("findings", []) or []:
                if isinstance(row, dict):
                    deduped[_finding_identity(row)] = row
        for row in _bulk_ingested_findings_for_tenant(tenant_id):
            if isinstance(row, dict):
                deduped.setdefault(_finding_identity(row), row)

        for row in deduped.values():
            if not _row_matches_scope(row, filters):
                continue
            if processed >= _ACCOUNT_SUMMARY_MAX_ROWS:
                truncated = True
                break
            processed += 1
            dom = _row_domain(row)
            bucket = _bucket(str(row.get("severity") or ""), lanes[dom])
            lanes[dom][bucket] += 1
            counts[dom] += 1
            total_severity[bucket] += 1
            region = str(row.get("region") or "").strip()
            if region:
                regions.add(region)
            environment = str(row.get("environment") or "").strip()
            if environment:
                environments.add(environment)
            raw_asset = row.get("asset")
            asset: dict[str, Any] = raw_asset if isinstance(raw_asset, dict) else {}
            identifier = str(asset.get("identifier") or asset.get("name") or "").strip()
            asset_type = str(asset.get("asset_type") or "").strip().lower()
            if identifier:
                asset_ids.add(identifier)
                if asset_type in _IDENTITY_ASSET_TYPES:
                    identity_ids.add(identifier)
                if asset_type in _ROLE_ASSET_TYPES:
                    role_ids.add(identifier)

    compliance = (
        _compliance_for_account(jobs_newest_first, provider, canonical_ref)
        if canonical_ref
        else {"evaluated": 0, "passed": 0, "failed": 0, "pass_rate": None, "benchmarks": []}
    )
    compliance["href"] = _account_findings_href(canonical_ref, provider, domain="cspm")

    findings_total = sum(counts.values())
    domains = [
        {
            "domain": dom,
            "label": _COVERAGE_LABELS[dom],
            "count": counts[dom],
            "severity": {key: lanes[dom][key] for key in _ALL_SEVERITY_KEYS},
            "href": _account_findings_href(canonical_ref, provider, domain=dom),
        }
        for dom in _COVERAGE_DOMAINS
    ]

    return {
        "schema_version": "cloud.account.summary.v1",
        "tenant_id": tenant_id,
        "account_ref": canonical_ref,
        "provider": provider,
        "account": account,
        "regions": sorted(regions),
        "environments": sorted(environments),
        "findings_total": findings_total,
        "severity": {key: total_severity[key] for key in _ALL_SEVERITY_KEYS},
        "domains": domains,
        "compliance": compliance,
        "assets": {
            "count": len(asset_ids),
            "href": f"/inventory/assets?provider={provider}" if provider else "/inventory/assets",
            "note": "Distinct assets referenced by findings in this account.",
        },
        "identities": {
            "count": len(identity_ids),
            "roles": len(role_ids),
            "note": "Derived from finding assets; full IAM role/grant enumeration is a follow-up.",
        },
        "drill": {
            "findings_href": _account_findings_href(canonical_ref, provider),
            "graph_href": f"/graph?provider={provider}" if provider else "/graph",
        },
        "truncated": truncated,
        "empty": findings_total == 0 and compliance["evaluated"] == 0,
        "note": (
            "Read-only aggregation over already-ingested findings and stored CIS benchmark runs, "
            "scoped to this provider+account. No live provider scan is triggered."
        ),
    }


@router.get("/cloud/accounts/{account_ref}/summary")
async def cloud_account_summary(
    request: Request,
    account_ref: str,
    _role: Any = _READ_DEP,
) -> dict[str, Any]:
    """Per-account, end-to-end posture drill for one cloud account (issue #3931).

    Returns findings by security domain (each severity strip summing to its lane
    count), stored CIS/compliance pass-rate, an asset count, and an
    identity/role count — everything scoped to ``account_ref`` (e.g.
    ``aws:123456789012``). Read-only: composes the #3946 rollup + scope filters
    over already-ingested evidence and never triggers a provider scan.

    Canonicalized + tenant-scoped; a malformed or unknown account returns an
    honest empty summary (all five lanes at zero, ``pass_rate: null``) rather
    than raising. The read runs off the event loop under the shared findings
    backpressure guard so a burst of account views cannot starve ``/health``.
    """
    tenant_id = _tenant(request)
    try:
        async with adaptive_backpressure("findings"):
            return await anyio.to_thread.run_sync(_build_account_summary, tenant_id, account_ref)
    except BackpressureRejectedError as exc:
        raise HTTPException(
            status_code=429,
            detail=exc.to_dict(),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc
