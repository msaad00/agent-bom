"""Distinct cloud scopes (``provider:account``) evidenced by stored scan results.

A cloud account counts as covered once a completed scan for it is stored — a
brokered connection scan or a CLI ``cloud ... --push-url`` push alike. Scopes
come from the CIS benchmark bundles (which name the account/subscription/
project they assessed) and from the ``account_ref`` carried on findings.
"""

from __future__ import annotations

from typing import Any, Iterable

from agent_bom.finding_scope import account_ref_from_arn, normalize_account_ref

CLOUD_PROVIDERS = frozenset({"aws", "azure", "gcp", "snowflake", "databricks", "oci"})

_CIS_SCOPE_KEYS: tuple[tuple[str, tuple[str, ...], tuple[str, ...]], ...] = (
    ("aws", ("cis_benchmark", "cis_benchmark_data"), ("account_id", "accounts_scanned")),
    ("azure", ("azure_cis_benchmark", "azure_cis_benchmark_data"), ("subscription_id", "subscriptions_scanned")),
    ("gcp", ("gcp_cis_benchmark", "gcp_cis_benchmark_data"), ("project_id", "projects_scanned")),
    ("snowflake", ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data"), ("account",)),
)

_CONNECTION_ACCOUNT_PARAMS = {
    "azure": ("subscription_id",),
    "gcp": ("project_id",),
    "snowflake": ("account", "account_identifier"),
    "databricks": ("workspace_id", "host"),
}


def _cloud_ref(value: Any, provider: str | None = None) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    raw = value.strip()
    if provider is None:
        head, sep, tail = raw.partition(":")
        if not sep or not tail.strip():
            return None
        provider = head
    ref = normalize_account_ref(provider, raw)
    if ref is None or ref.partition(":")[0] not in CLOUD_PROVIDERS:
        return None
    return ref


def scopes_from_result(result: Any) -> set[str]:
    """Return the normalized cloud account refs a stored scan result assessed."""
    if not isinstance(result, dict):
        return set()
    scopes: set[str] = set()
    for provider, bundle_keys, scope_keys in _CIS_SCOPE_KEYS:
        for bundle_key in bundle_keys:
            bundle = result.get(bundle_key)
            if not isinstance(bundle, dict):
                continue
            for scope_key in scope_keys:
                value = bundle.get(scope_key)
                values = value if isinstance(value, list) else [value]
                for item in values:
                    ref = _cloud_ref(item, provider)
                    if ref:
                        scopes.add(ref)
    for finding in result.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        asset = finding.get("asset")
        candidates = [finding.get("account_ref")]
        if isinstance(asset, dict):
            candidates.append(asset.get("account_ref"))
        for candidate in candidates:
            ref = _cloud_ref(candidate)
            if ref:
                scopes.add(ref)
    return scopes


def connection_scope(record: Any) -> str:
    """Normalized account ref for a cloud connection, or a per-connection key."""
    provider = str(getattr(record, "provider", "") or "").strip().lower()
    account: str | None = None
    if provider == "aws":
        account = account_ref_from_arn(str(getattr(record, "role_ref", "") or ""))
    params = getattr(record, "auth_params", None) or {}
    for key in _CONNECTION_ACCOUNT_PARAMS.get(provider, ()):
        if account:
            break
        value = params.get(key) if isinstance(params, dict) else None
        account = str(value).strip() if value else None
    return normalize_account_ref(provider, account) or f"connection:{getattr(record, 'id', '')}"


def _job_timestamp(job: Any) -> str | None:
    stamp = getattr(job, "completed_at", None) or getattr(job, "created_at", None)
    return str(stamp) if stamp else None


def scanned_cloud_scopes(jobs: Iterable[Any]) -> dict[str, Any]:
    """Distinct cloud scopes across completed jobs plus the newest such scan."""
    from agent_bom.api.models import JobStatus

    scopes: set[str] = set()
    last_scan_at: str | None = None
    for job in jobs:
        if getattr(job, "status", None) != JobStatus.DONE:
            continue
        found = scopes_from_result(getattr(job, "result", None))
        if not found:
            continue
        scopes |= found
        stamp = _job_timestamp(job)
        if stamp and (last_scan_at is None or stamp > last_scan_at):
            last_scan_at = stamp
    return {"scopes": sorted(scopes), "last_scan_at": last_scan_at}


def cloud_account_summary(connections: Iterable[Any], scanned: dict[str, Any] | None) -> dict[str, Any]:
    """Union connected and scanned cloud scopes into one tenant summary."""
    connection_list = list(connections)
    scanned = scanned or {"scopes": [], "last_scan_at": None}
    scopes = {connection_scope(record) for record in connection_list}
    scopes.update(scanned.get("scopes") or [])
    providers = {str(record.provider).lower() for record in connection_list if getattr(record, "provider", None)}
    providers.update(ref.partition(":")[0] for ref in scanned.get("scopes") or [])
    stamps = [str(record.last_scan_at) for record in connection_list if getattr(record, "last_scan_at", None)]
    if scanned.get("last_scan_at"):
        stamps.append(str(scanned["last_scan_at"]))
    return {
        "count": len(scopes),
        "connections": len(connection_list),
        "scanned_scopes": len(scanned.get("scopes") or []),
        "providers": sorted(providers),
        "last_scan_at": max(stamps) if stamps else None,
    }
