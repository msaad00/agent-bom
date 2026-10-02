"""Location boundaries used by exact-identity correlation and evidence readers."""

from collections.abc import Iterable

from agent_bom.graph.node import UnifiedNode

CORRELATION_IDENTITY_VERSION = "scoped-identity.v4"
IDENTIFIER_NAMESPACES = {"resource_arn": "arn", "provider_id": "resource_id", "stable_id": "canonical_id"}


def merged_identity_version(receipts: Iterable[object]) -> str:
    """Reprocessing a legacy join cannot repair its missing source scope."""
    return (
        CORRELATION_IDENTITY_VERSION
        if all(
            not receipt or isinstance(receipt, dict) and receipt.get("identity_version") == CORRELATION_IDENTITY_VERSION
            for receipt in receipts
        )
        else "legacy"
    )


def exact_identity_scope(node: UnifiedNode, *, basis: str, namespace: str, value: str) -> dict[str, str]:
    """Use recorded scope; preserve conflicts rather than guessing a location."""
    keys = ["cloud_provider", "cloud_account_id", "account_id", "tenant_id", "subscription_id", "project_id"]
    dimensions = []
    arn = value.split(":", 5) if namespace == "arn" else []
    qualified_arn = (
        len(arn) == 6
        and arn[0] == "arn"
        and bool(arn[1] and arn[2] and arn[5])
        and (bool(arn[3] and len(arn[4]) == 12 and arn[4].isascii() and arn[4].isdigit()) or (arn[2] == "s3" and not arn[3] and not arn[4]))
    )
    if basis in {"cloud_resource_id", "provider_identity_id", "runtime_stable_id"}:
        dimensions.append("cloud_provider")
        if not qualified_arn:
            keys.extend(["cluster_id", "cluster_arn", "region", "namespace"])
    if basis == "runtime_stable_id":
        keys.extend(["runtime_host_id", "environment"])
        dimensions.append("environment")
    scope = {key: str(node.attributes.get(key) or "").strip() for key in keys if str(node.attributes.get(key) or "").strip()}
    for key in dimensions:
        value = str(getattr(node.dimensions, key, "") or "").strip()
        if value:
            if key in scope and scope[key] != value:
                scope[f"conflicting_dimension_{key}"] = value
            scope.setdefault(key, value)
    # A fully-qualified ARN already carries its location. Collection metadata
    # cannot split it, but a contradictory recorded region is not a safe join.
    recorded_region = str(node.attributes.get("region") or "").strip()
    if qualified_arn and arn[3] and recorded_region and recorded_region != arn[3]:
        scope["conflicting_arn_region"] = recorded_region
    return scope


def container_occurrence(node: UnifiedNode) -> dict[str, object] | None:
    """Return recorded deployment identity; image digests never locate containers."""
    attrs = node.attributes
    scope = {
        key: str(attrs.get(key) or "").strip()
        for key in (
            "cloud_provider",
            "cloud_account_id",
            "account_id",
            "tenant_id",
            "subscription_id",
            "project_id",
            "cluster_id",
            "cluster_arn",
            "runtime_host_id",
            "environment",
        )
        if str(attrs.get(key) or "").strip()
    }
    for key in ("cloud_provider", "environment"):
        dimension = str(getattr(node.dimensions, key, "") or "").strip()
        if dimension:
            if key in scope and scope[key] != dimension:
                scope[f"conflicting_dimension_{key}"] = dimension
            scope.setdefault(key, dimension)
    located = bool(scope.get("cloud_provider")) and any(
        scope.get(key)
        for key in ("cluster_id", "cluster_arn", "runtime_host_id", "cloud_account_id", "account_id", "subscription_id", "project_id")
    )
    uid_key = "runtime_uid" if attrs.get("runtime_uid") else "container_id"
    uid = str(attrs.get(uid_key) or "").strip()
    if not uid and attrs.get("kubernetes_uid") and attrs.get("container_name") and (scope.get("cluster_id") or scope.get("cluster_arn")):
        uid_key = "kubernetes_container"
        uid = f"{attrs['kubernetes_uid']}:{attrs['container_name']}"
    if uid and located:
        return {"scope": scope, "uid_kind": uid_key, "runtime_uid": uid}
    return None
