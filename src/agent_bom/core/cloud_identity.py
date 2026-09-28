"""Provider-native cloud resource keys; display names never cross scope boundaries."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote


def cloud_resource_node_id(provider: str, kind: str, record: Mapping[str, Any], account: str, region: str) -> str:
    """Prefer a qualified native ID, otherwise bind local IDs/names to recorded scope.

    Azure ARM IDs are case-insensitive. AWS ARN resource components and GCP
    native paths retain their case. A name-only fallback is explicitly separate
    from a native identifier, and missing scope is never replaced by another
    account's scope. Original provider identifiers stay in node evidence.
    """
    provider = provider.strip().casefold()
    native = str(
        record.get("arn")
        or record.get("id")
        or record.get("resource_id")
        or record.get("vpc_id")
        or record.get("self_link")
        or record.get("selfLink")
        or ""
    ).strip()
    if provider == "azure" and native.lower().startswith(("/subscriptions/", "/tenants/")):
        key = native.rstrip("/").casefold()
    elif provider == "aws" and native.startswith("arn:") and len(native.split(":", 5)) == 6:
        key = native
    elif provider == "gcp" and native.startswith(("projects/", "folders/", "organizations/", "https://", "//")):
        key = native.rstrip("/")
    else:
        account = str(record.get("account_id") or record.get("subscription_id") or record.get("project_id") or account or "").strip()
        location = str(record.get("zone") or record.get("location") or record.get("region") or region or "").strip()
        group = str(record.get("resource_group") or "").strip()
        value = native or str(record.get("name") or "").strip()
        parts = [account, location, group, "native" if native else "name", value]
        if provider == "azure":
            parts = [part.casefold() for part in parts]
        key = "scoped/" + "/".join(quote(part, safe="") for part in parts)
    return f"cloud_resource:{provider}:{kind}:{key}"
