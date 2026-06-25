"""GCP general cloud-asset inventory — estate-wide, read-only, agentless.

Unlike :mod:`agent_bom.cloud.gcp` (which discovers *AI* runtimes: Vertex AI,
Cloud Functions, GKE, Cloud Run), this module enumerates the general GCP estate
so that a resource with **no** CIS finding, IaC target, or discovered AI runtime
still becomes a first-class graph node. That feeds the CNAPP exposure overlay,
the CIEM effective-permissions overlay, and the DSPM tiers, which were
previously starved of inventory input.

Three resource classes are enumerated project-wide (NOT filtered to findings):

1. **GCS buckets**            → emitted as ``DATA_STORE``-signalling
   ``CLOUD_RESOURCE`` so the DSPM / ``STORES`` / ``EXPOSED_TO`` overlays apply.
2. **Compute instances + firewall rules** → emitted as ``CLOUD_RESOURCE``.
3. **Service Accounts**       → emitted as identity principals with a
   ``HAS_PERMISSION``-ready structure.

This scanner is **opt-in** and **default OFF**. It runs only when
``AGENT_BOM_GCP_INVENTORY`` is truthy, mirroring the platform's other
optional-feature gates (e.g. ``AGENT_BOM_CLOUD_INVENTORY``).

Trust posture: read-only (``ScanMode.CLOUD_READ_ONLY``), reference-only, and
agentless. Authentication is **token / ADC only** — no passwords — via
Application Default Credentials (env service-account JSON, workload identity,
gcloud user / impersonation tokens). Only ``list`` / ``get`` APIs are called —
no write APIs, no object-content reads, no credential exfiltration. SDK absence
or missing credentials degrades to an empty inventory plus a clear status,
never a crash.

Requires ``google-cloud-storage``, ``google-cloud-compute``, and
``google-cloud-iam``. Install with::

    pip install 'agent-bom[gcp]'
"""

from __future__ import annotations

import logging
import os
from typing import Any

from agent_bom.discovery_envelope import DiscoveryEnvelope, RedactionStatus, ScanMode

from .normalization import sanitize_discovery_warning

logger = logging.getLogger(__name__)

# Opt-in env flag. Default OFF — estate-wide enumeration must be explicitly
# requested by an operator. Mirrors the other AGENT_BOM_* feature gates.
INVENTORY_ENV_FLAG = "AGENT_BOM_GCP_INVENTORY"

_TRUTHY = {"1", "true", "yes", "on"}

# Read-only IAM permissions this scanner is allowed to exercise, by resource
# class. Kept here so the per-run discovery envelope `permissions_used` stays
# honest: the producer owns the catalog, not external docs.
_GCP_STORAGE_PERMISSIONS: tuple[str, ...] = (
    "storage.buckets.list",
    "storage.buckets.getIamPolicy",
)
_GCP_COMPUTE_PERMISSIONS: tuple[str, ...] = (
    "compute.instances.list",
    "compute.firewalls.list",
)
_GCP_IAM_PERMISSIONS: tuple[str, ...] = (
    "iam.serviceAccounts.list",
    "resourcemanager.projects.getIamPolicy",
)

# Open-to-the-world source ranges that mark a firewall rule as internet-facing.
# The CNAPP overlay keys off this `network_exposure` shape.
_INTERNET_RANGES = {"0.0.0.0/0", "::/0"}

# Members that mark a bucket IAM policy as publicly accessible.
_PUBLIC_MEMBERS = {"allusers", "allauthenticatedusers"}

# Privilege ranking shared with the AWS path so cross-provider CIEM reasoning
# (OVERPERMISSIONED_TO_SENSITIVE, effective-permissions) treats levels uniformly.
_PRIVILEGE_RANK = {"admin": 3, "write": 2, "read": 1, "unknown": 0}

# Canonical predefined GCP roles → privilege level (no extra API call needed).
_GCP_ROLE_PRIVILEGE: dict[str, str] = {
    "roles/owner": "admin",
    "roles/editor": "write",
    "roles/viewer": "read",
    "roles/browser": "read",
}


def _classify_role_privilege(role: str) -> str:
    """Classify a single GCP IAM role into admin / write / read / unknown.

    Mirrors the AWS managed-policy classifier: the basic Owner/Editor/Viewer
    roles map directly; any ``*Admin`` role is admin; any ``*Viewer`` / ``*Reader``
    role is read. Everything else stays ``unknown`` — never an inflated guess.
    """
    name = str(role or "").strip()
    if not name:
        return "unknown"
    lowered = name.lower()
    if lowered in _GCP_ROLE_PRIVILEGE:
        return _GCP_ROLE_PRIVILEGE[lowered]
    # Strip the leaf after the last dot/slash for the "*Admin"/"*Viewer" suffix test.
    leaf = lowered.rsplit("/", 1)[-1].rsplit(".", 1)[-1]
    if leaf.endswith("admin") or "admin" in leaf:
        return "admin"
    if "owner" in leaf:
        return "admin"
    if "editor" in leaf or leaf.endswith("writer") or leaf.endswith("write"):
        return "write"
    if leaf.endswith("viewer") or leaf.endswith("reader") or leaf.endswith("read") or "viewer" in leaf or "reader" in leaf:
        return "read"
    return "unknown"


def _highest_privilege(roles: list[str]) -> str:
    """Return the most-privileged level across a principal's bound roles."""
    best = "unknown"
    for role in roles:
        level = _classify_role_privilege(role)
        if _PRIVILEGE_RANK.get(level, 0) > _PRIVILEGE_RANK.get(best, 0):
            best = level
    return best


def inventory_enabled() -> bool:
    """Return whether estate-wide GCP inventory enumeration is opted in.

    Default OFF. Operators enable it by setting ``AGENT_BOM_GCP_INVENTORY`` to
    a truthy value (``1`` / ``true`` / ``yes`` / ``on``).
    """
    return os.environ.get(INVENTORY_ENV_FLAG, "").strip().lower() in _TRUTHY


def _derive_default_project() -> tuple[str, str]:
    """Best-effort ``(project_id, note)`` from Application Default Credentials.

    ``google.auth.default()`` resolves the project the same way every google
    client does — from a service-account key's ``project_id``, the gcloud config,
    or the metadata server — so a key/ADC connection needs no explicit
    ``GOOGLE_CLOUD_PROJECT``. Returns ``("", note)`` on any failure; never raises.
    """
    try:
        from google import auth as google_auth
    except ImportError:
        return "", "google-auth not installed; cannot auto-derive the project. Set GOOGLE_CLOUD_PROJECT."
    try:
        _creds, project = google_auth.default()
    except Exception as exc:  # noqa: BLE001 — ADC resolution must not crash a scan
        return "", sanitize_discovery_warning(exc)
    if not project:
        return "", "No GCP project resolved from Application Default Credentials. Set GOOGLE_CLOUD_PROJECT."
    return str(project), ""


_IMPERSONATE_ENV = "AGENT_BOM_GCP_IMPERSONATE_SA"
_IMPERSONATE_SCOPES = ("https://www.googleapis.com/auth/cloud-platform",)


def _resolve_impersonation(credentials: Any, warnings: list[str]) -> Any:
    """Return credentials impersonating the read-only SA named by the env var.

    When ``AGENT_BOM_GCP_IMPERSONATE_SA`` is set and no explicit credential was
    passed, wrap the ambient ADC in short-lived impersonated credentials for that
    service account, so every discovery call runs as a least-privilege read-only
    identity without a service-account key (the recommended path where keys are
    org-disabled). Read-only and fail-safe: any error falls back to the original
    credentials with a warning, never raises.
    """
    if credentials is not None:
        return credentials
    target = os.environ.get(_IMPERSONATE_ENV, "").strip()
    if not target:
        return credentials
    try:
        from google import auth as google_auth
        from google.auth import impersonated_credentials
    except ImportError:
        warnings.append("google-auth not installed; cannot impersonate the GCP service account.")
        return credentials
    try:
        source, _ = google_auth.default()
        return impersonated_credentials.Credentials(
            source_credentials=source,
            target_principal=target,
            target_scopes=list(_IMPERSONATE_SCOPES),
        )
    except Exception as exc:  # noqa: BLE001 — impersonation failure degrades, never crashes
        warnings.append(f"GCP service-account impersonation of {target} failed: {sanitize_discovery_warning(exc)}")
        return credentials


def discover_inventory(
    project_id: str | None = None,
    *,
    credentials: Any = None,
    include_storage: bool = True,
    include_compute: bool = True,
    include_iam: bool = True,
    force: bool = False,
) -> dict[str, Any]:
    """Enumerate the general GCP estate (GCS, instances + firewalls, SAs).

    Returns a JSON-serialisable inventory payload destined for
    ``report_json["cloud_inventory"]``; the graph builder turns it into nodes.

    The payload always carries a ``status`` string so callers can surface a
    clear reason when nothing was enumerated:

    - ``"disabled"``        — the feature flag is off and ``force`` was not set.
    - ``"sdk_missing"``     — google-cloud SDKs are not installed.
    - ``"no_project"``      — no project id resolved.
    - ``"ok"``              — enumeration ran (possibly with per-service warnings).

    Never raises: SDK absence, missing credentials, and per-service access
    denials all degrade to an empty (or partial) inventory plus warnings.

    Authentication is token / Application Default Credentials only (no
    passwords). When ``credentials`` is not supplied, the google client
    libraries resolve ADC, which acquires short-lived tokens from env
    service-account JSON, workload identity, or gcloud user / impersonation.
    """
    resolved_project = project_id or os.environ.get("GOOGLE_CLOUD_PROJECT", "")
    empty: dict[str, Any] = {
        "provider": "gcp",
        "status": "disabled",
        "project_id": resolved_project,
        "account_id": resolved_project,
        "region": "",
        "buckets": [],
        "instances": [],
        "firewalls": [],
        "service_accounts": [],
        "warnings": [],
        "discovery_envelope": None,
    }

    if not force and not inventory_enabled():
        return empty

    try:
        from google.cloud import storage  # noqa: F401
    except ImportError:
        return {
            **empty,
            "status": "sdk_missing",
            "warnings": ["google-cloud-storage is required for GCP inventory. Install with: pip install 'agent-bom[gcp]'"],
        }

    derive_note = ""
    if not resolved_project:
        resolved_project, derive_note = _derive_default_project()
        if not resolved_project:
            return {
                **empty,
                "status": "no_project",
                "warnings": [derive_note or "No GCP project found. Set GOOGLE_CLOUD_PROJECT or provide project_id."],
            }
        empty["project_id"] = resolved_project
        empty["account_id"] = resolved_project

    warnings: list[str] = []
    if derive_note:
        warnings.append(derive_note)
    # Keyless least-privilege connection: when AGENT_BOM_GCP_IMPERSONATE_SA names
    # a read-only service account, impersonate it (from the ambient ADC) so every
    # discovery runs AS that SA — the recommended path where SA keys are
    # org-disabled, matching AWS's read-only profile and Snowflake's role.
    credentials = _resolve_impersonation(credentials, warnings)
    buckets: list[dict[str, Any]] = []
    instances: list[dict[str, Any]] = []
    firewalls: list[dict[str, Any]] = []
    service_accounts: list[dict[str, Any]] = []

    if include_storage:
        buckets = _discover_buckets(resolved_project, credentials=credentials, warnings=warnings)
    if include_compute:
        instances = _discover_instances(resolved_project, credentials=credentials, warnings=warnings)
        firewalls = _discover_firewalls(resolved_project, credentials=credentials, warnings=warnings)
    if include_iam:
        iam_bindings = _discover_project_iam_bindings(resolved_project, credentials=credentials, warnings=warnings)
        service_accounts = _discover_service_accounts(
            resolved_project, credentials=credentials, warnings=warnings, iam_bindings=iam_bindings
        )

    permissions_used: list[str] = []
    if include_storage:
        permissions_used.extend(_GCP_STORAGE_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_GCP_COMPUTE_PERMISSIONS)
    if include_iam:
        permissions_used.extend(_GCP_IAM_PERMISSIONS)

    envelope = DiscoveryEnvelope(
        scan_mode=ScanMode.CLOUD_READ_ONLY,
        discovery_scope=(f"gcp:project/{resolved_project}",),
        permissions_used=tuple(sorted(set(permissions_used))),
        redaction_status=RedactionStatus.CENTRAL_SANITIZER_APPLIED,
    )

    return {
        "provider": "gcp",
        "status": "ok",
        "project_id": resolved_project,
        "account_id": resolved_project,
        "region": "",
        "buckets": buckets,
        "instances": instances,
        "firewalls": firewalls,
        "service_accounts": service_accounts,
        "warnings": warnings,
        "discovery_envelope": envelope.to_dict(),
    }


# ---------------------------------------------------------------------------
# GCS buckets (project-wide list)
# ---------------------------------------------------------------------------


def _discover_buckets(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every GCS bucket in the project (read-only).

    Public-access posture is read from the bucket IAM policy (``allUsers`` /
    ``allAuthenticatedUsers`` bindings) — never from object contents. Buckets
    become ``DATA_STORE``-signalling nodes so DSPM and exposure overlays apply.
    """
    try:
        from google.cloud import storage
    except ImportError:
        warnings.append("google-cloud-storage not installed. Skipping GCS bucket inventory.")
        return []

    buckets: list[dict[str, Any]] = []
    try:
        client = storage.Client(project=project_id, credentials=credentials)
        for bucket in client.list_buckets():
            name = str(getattr(bucket, "name", "") or "").strip()
            if not name:
                continue
            buckets.append(
                {
                    "name": name,
                    "id": f"//storage.googleapis.com/{name}",
                    "location": str(getattr(bucket, "location", "") or ""),
                    "publicly_accessible": _bucket_public(bucket, name, warnings),
                    "tags": _clean_labels(getattr(bucket, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list GCS buckets: {sanitize_discovery_warning(exc)}")
    return buckets


def _bucket_public(bucket: Any, name: str, warnings: list[str]) -> bool:
    """Best-effort public determination from the bucket IAM policy only.

    A bucket is treated as public when its IAM policy grants any role to
    ``allUsers`` or ``allAuthenticatedUsers``. Errors degrade to ``False``
    (unknown) with a warning — never a guess that inflates risk.
    """
    get_policy = getattr(bucket, "get_iam_policy", None)
    if not callable(get_policy):
        return False
    try:
        policy = get_policy()
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not read IAM policy for GCS bucket {name}: {sanitize_discovery_warning(exc)}")
        return False
    for binding in _policy_bindings(policy):
        members = binding.get("members", []) or []
        if any(str(member).split(":", 1)[0].lower() in _PUBLIC_MEMBERS for member in members):
            return True
    return False


def _policy_bindings(policy: Any) -> list[dict[str, Any]]:
    raw = getattr(policy, "bindings", None)
    if raw is None and isinstance(policy, dict):
        raw = policy.get("bindings")
    bindings: list[dict[str, Any]] = []
    for binding in raw or []:
        if isinstance(binding, dict):
            bindings.append(binding)
        else:
            bindings.append(
                {
                    "role": str(getattr(binding, "role", "") or ""),
                    "members": list(getattr(binding, "members", []) or []),
                }
            )
    return bindings


# ---------------------------------------------------------------------------
# Compute instances + firewall rules (project-wide aggregated list)
# ---------------------------------------------------------------------------


def _discover_instances(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate all Compute Engine instances in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping Compute instance inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        client = compute_v1.InstancesClient(credentials=credentials)
        for _zone, scoped_list in client.aggregated_list(project=project_id):
            for instance in getattr(scoped_list, "instances", None) or []:
                name = str(getattr(instance, "name", "") or "").strip()
                if not name:
                    continue
                instances.append(_normalize_instance(instance, name=name, project_id=project_id))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Compute instances: {sanitize_discovery_warning(exc)}")
    return instances


def _normalize_instance(instance: Any, *, name: str, project_id: str) -> dict[str, Any]:
    public_ip = ""
    private_ip = ""
    networks: list[str] = []
    for interface in getattr(instance, "network_interfaces", None) or []:
        private_ip = private_ip or str(getattr(interface, "network_i_p", "") or getattr(interface, "network_ip", "") or "")
        network_leaf = _leaf(getattr(interface, "network", ""))
        if network_leaf and network_leaf not in networks:
            networks.append(network_leaf)
        for access in getattr(interface, "access_configs", None) or []:
            nat_ip = str(getattr(access, "nat_i_p", "") or getattr(access, "nat_ip", "") or "")
            if nat_ip:
                public_ip = nat_ip
                break
    service_accounts = [
        str(getattr(sa, "email", "") or "") for sa in (getattr(instance, "service_accounts", None) or []) if getattr(sa, "email", "")
    ]
    return {
        "instance_id": str(getattr(instance, "id", "") or "") or name,
        "name": name,
        "instance_type": _leaf(getattr(instance, "machine_type", "")),
        "zone": _leaf(getattr(instance, "zone", "")),
        "status": str(getattr(instance, "status", "") or ""),
        "public_ip": public_ip,
        "private_ip": private_ip,
        # The network each interface attaches to — the join key a firewall rule
        # matches on (a rule applies to instances on its target network).
        "network": networks[0] if networks else "",
        "networks": networks,
        "network_tags": list(getattr(getattr(instance, "tags", None), "items", None) or []),
        "service_accounts": service_accounts,
        "labels": _clean_labels(getattr(instance, "labels", None)),
        "project_id": project_id,
    }


def _discover_firewalls(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate all VPC firewall rules in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping firewall inventory.")
        return []

    firewalls: list[dict[str, Any]] = []
    try:
        client = compute_v1.FirewallsClient(credentials=credentials)
        for rule in client.list(project=project_id):
            name = str(getattr(rule, "name", "") or "").strip()
            if not name:
                continue
            firewalls.append(_normalize_firewall(rule, name=name, project_id=project_id))
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list firewall rules: {sanitize_discovery_warning(exc)}")
    return firewalls


def _normalize_firewall(rule: Any, *, name: str, project_id: str) -> dict[str, Any]:
    exposure = _firewall_internet_exposure(rule)
    source_ranges = [str(r) for r in (getattr(rule, "source_ranges", None) or []) if r]
    # Target tags / target service accounts scope a rule to specific instances.
    # An EMPTY target set means the rule applies to ALL instances on its network.
    target_tags = [str(t) for t in (getattr(rule, "target_tags", None) or []) if t]
    target_service_accounts = [str(sa) for sa in (getattr(rule, "target_service_accounts", None) or []) if sa]
    return {
        "group_id": name,
        "name": name,
        "network": _leaf(getattr(rule, "network", "")),
        "direction": str(getattr(rule, "direction", "") or "").upper(),
        "internet_exposed": bool(exposure),
        "network_exposure": exposure,
        "source_ranges": source_ranges,
        "target_tags": target_tags,
        "target_service_accounts": target_service_accounts,
        "project_id": project_id,
    }


def _firewall_internet_exposure(rule: Any) -> list[dict[str, Any]]:
    """Return internet-facing ingress allow rules in the CNAPP overlay's shape."""
    direction = str(getattr(rule, "direction", "") or "INGRESS").upper()
    if direction not in ("", "INGRESS"):
        return []
    if not (getattr(rule, "allowed", None) or []):
        return []
    source_ranges = [str(r) for r in (getattr(rule, "source_ranges", None) or []) if r]
    if not any(src in _INTERNET_RANGES for src in source_ranges):
        return []
    exposure: list[dict[str, Any]] = []
    for allowed in getattr(rule, "allowed", None) or []:
        protocol = str(getattr(allowed, "I_p_protocol", "") or getattr(allowed, "ip_protocol", "") or "tcp").lower()
        ports = list(getattr(allowed, "ports", None) or [])
        if not ports:
            exposure.append({"scope": "internet", "from_port": None, "to_port": None, "protocol": protocol})
            continue
        for port in ports:
            from_port, to_port = _parse_port(str(port))
            exposure.append({"scope": "internet", "from_port": from_port, "to_port": to_port, "protocol": protocol})
    return exposure


def _parse_port(text: str) -> tuple[int | None, int | None]:
    value = text.strip()
    if not value:
        return None, None
    if "-" in value:
        low, _, high = value.partition("-")
        return _safe_int(low), _safe_int(high)
    port = _safe_int(value)
    return port, port


def _safe_int(value: str) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Service accounts (project-wide list)
# ---------------------------------------------------------------------------


def _discover_project_iam_bindings(project_id: str, *, credentials: Any, warnings: list[str]) -> dict[str, list[str]]:
    """Read the project IAM policy (read-only) → ``{member: [roles…]}``.

    Calls ``cloudresourcemanager`` ``projects.getIamPolicy`` and inverts the
    role→members bindings into a member→roles map so each principal carries the
    roles bound to it. The member key is the bare identity (e.g.
    ``svc@p.iam.gserviceaccount.com``) with the ``serviceAccount:`` / ``user:`` /
    ``group:`` prefix stripped, matching the SA email used elsewhere. Degrades to
    an empty map plus a warning on any error — never raises.
    """
    bindings_by_member: dict[str, list[str]] = {}
    try:
        from google.cloud import resourcemanager_v3
    except ImportError:
        warnings.append("google-cloud-resource-manager not installed. Skipping project IAM-binding discovery.")
        return bindings_by_member
    try:
        from google.iam.v1 import iam_policy_pb2

        client = resourcemanager_v3.ProjectsClient(credentials=credentials)
        request = iam_policy_pb2.GetIamPolicyRequest(resource=f"projects/{project_id}")
        policy = client.get_iam_policy(request=request)
        for binding in _policy_bindings(policy):
            role = str(binding.get("role", "") or "")
            if not role:
                continue
            for member in binding.get("members", []) or []:
                key = str(member).split(":", 1)[-1].strip().lower() if ":" in str(member) else str(member).strip().lower()
                if not key:
                    continue
                roles = bindings_by_member.setdefault(key, [])
                if role not in roles:
                    roles.append(role)
    except Exception as exc:  # noqa: BLE001 — IAM-policy read must never sink a scan
        warnings.append(f"Could not read project IAM policy: {sanitize_discovery_warning(exc)}")
    return bindings_by_member


def _discover_service_accounts(
    project_id: str,
    *,
    credentials: Any,
    warnings: list[str],
    iam_bindings: dict[str, list[str]] | None = None,
) -> list[dict[str, Any]]:
    """Enumerate all service accounts in the project (read-only).

    Each service account becomes a ``service_account`` graph node carrying its
    unique id and the project IAM roles bound to it, classified into a
    ``privilege_level`` (admin / write / read / unknown) so the
    effective-permissions overlay and ``OVERPERMISSIONED_TO_SENSITIVE`` /
    CIEM reasoning fire on GCP — mirroring the AWS IAM path. Privilege defaults to
    ``unknown`` when no binding is found — inventory never guesses an inflated level.
    """
    try:
        from google.cloud import iam_admin_v1
    except ImportError:
        warnings.append("google-cloud-iam not installed. Skipping service-account inventory.")
        return []

    bindings = iam_bindings or {}
    accounts: list[dict[str, Any]] = []
    try:
        client = iam_admin_v1.IAMClient(credentials=credentials)
        request = iam_admin_v1.ListServiceAccountsRequest(name=f"projects/{project_id}")
        for account in client.list_service_accounts(request=request):
            email = str(getattr(account, "email", "") or "").strip()
            if not email:
                continue
            roles = list(bindings.get(email.lower(), []))
            policies = [
                {
                    "policy_id": role,
                    "policy_name": role,
                    "attachment_type": "iam-binding",
                    "privilege_level": _classify_role_privilege(role),
                    "source_field": "projects.getIamPolicy.bindings",
                }
                for role in roles
            ]
            accounts.append(
                {
                    "principal_type": "service-account",
                    "name": str(getattr(account, "display_name", "") or "") or email,
                    "arn": email,
                    "principal_id": str(getattr(account, "unique_id", "") or "") or email,
                    "email": email,
                    "disabled": bool(getattr(account, "disabled", False)),
                    "account_id": project_id,
                    "roles": roles,
                    "policies": policies,
                    "trust_principals": [],
                    "privilege_level": _highest_privilege(roles),
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list service accounts: {sanitize_discovery_warning(exc)}")
    return accounts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _leaf(value: Any) -> str:
    """Return the last path segment of a GCP self-link / type URL, else ''."""
    text = str(value or "").strip()
    if not text:
        return ""
    return text.rsplit("/", 1)[-1]


def _clean_labels(labels: Any) -> dict[str, str]:
    if not isinstance(labels, dict):
        return {}
    return {str(key): str(value) for key, value in labels.items() if key is not None}


__all__ = [
    "INVENTORY_ENV_FLAG",
    "discover_inventory",
    "inventory_enabled",
]
