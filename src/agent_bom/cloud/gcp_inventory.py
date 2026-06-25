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
from concurrent.futures import ThreadPoolExecutor, as_completed
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
# Estate-breadth read-only permissions exercised by the extended discoverers
# (GKE / Cloud Run / Cloud Functions / Cloud SQL / VPC / disks / Pub/Sub). Kept
# explicit so the discovery envelope's `permissions_used` stays honest.
_GCP_ESTATE_PERMISSIONS: tuple[str, ...] = (
    "container.clusters.list",
    "run.services.list",
    "cloudfunctions.functions.list",
    "cloudsql.instances.list",
    "compute.networks.list",
    "compute.subnetworks.list",
    "compute.disks.list",
    "pubsub.topics.list",
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


# Opt-in flag to fan a single scan across EVERY project in the org/folder tree —
# the GCP counterpart of AWS Organizations multi-account and Azure
# multi-subscription fan-out. Default OFF; requires AGENT_BOM_GCP_INVENTORY too.
ALL_PROJECTS_ENV_FLAG = "AGENT_BOM_GCP_ALL_PROJECTS"
# Defensive cap so an org with thousands of projects can't run unbounded without
# an operator opting into a larger budget. Mirrors Azure's subscription cap.
_MAX_PROJECTS = int(os.environ.get("AGENT_BOM_GCP_MAX_PROJECTS", "200") or "200")


def all_projects_enabled() -> bool:
    """Whether to fan a single scan across every project in the org/folder tree."""
    return os.environ.get(ALL_PROJECTS_ENV_FLAG, "").strip().lower() in _TRUTHY


def discover_all_project_inventories(credentials: Any = None, *, force: bool = False) -> list[dict[str, Any]]:
    """Inventory EVERY project in the org/folder tree (multi-project fan-out).

    The GCP counterpart of the AWS Organizations multi-account enumeration and
    the Azure multi-subscription fan-out: discover the project set from the
    organization → folders → projects hierarchy, then run the per-project
    inventory for each concurrently (partitioned by ``project_id`` so the graph
    keeps every project as a distinct account under the org ``CONTAINS`` tree).
    Read-only; impersonated credentials are threaded into every per-project call.

    Returns a LIST of per-project inventory payloads (the exact shape the graph
    builder's ``_iter_cloud_inventories`` consumes). Falls back to the single
    ambient ``GOOGLE_CLOUD_PROJECT`` when the org tree is unavailable (a
    standalone project, or a credential without org-level read). Never raises.
    """
    if not force and not inventory_enabled():
        return []

    warnings: list[str] = []
    resolved = _resolve_impersonation(credentials, warnings)

    try:
        from agent_bom.cloud import gcp_organizations

        project_ids = gcp_organizations.list_project_ids(resolved, force=force)
    except Exception as exc:  # noqa: BLE001 — org enumeration failure must degrade
        logger.warning("GCP org project enumeration failed: %s", sanitize_discovery_warning(exc))
        project_ids = []

    if not project_ids:
        single = os.environ.get("GOOGLE_CLOUD_PROJECT", "").strip()
        project_ids = [single] if single else []
    if not project_ids:
        return []

    capped = project_ids[:_MAX_PROJECTS]
    if len(project_ids) > _MAX_PROJECTS:
        logger.warning(
            "GCP multi-project scan capped at %d of %d projects (set AGENT_BOM_GCP_MAX_PROJECTS to raise).",
            _MAX_PROJECTS,
            len(project_ids),
        )

    payloads: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(capped))) as executor:
        futures = {executor.submit(discover_inventory, project_id=pid, credentials=resolved, force=True): pid for pid in capped}
        for future in as_completed(futures):
            try:
                payloads.append(future.result())
            except Exception as exc:  # noqa: BLE001 — one project's failure must not sink the rest
                logger.warning(
                    "GCP inventory failed for project %s: %s",
                    futures[future],
                    sanitize_discovery_warning(exc),
                )
    return payloads


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
    include_containers: bool = True,
    include_serverless: bool = True,
    include_databases: bool = True,
    include_networks: bool = True,
    include_disks: bool = True,
    include_messaging: bool = True,
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
        "gke_clusters": [],
        "cloud_run_services": [],
        "cloud_functions": [],
        "cloud_sql_instances": [],
        "vpc_networks": [],
        "disks": [],
        "pubsub_topics": [],
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
    gke_clusters: list[dict[str, Any]] = []
    cloud_run_services: list[dict[str, Any]] = []
    cloud_functions: list[dict[str, Any]] = []
    cloud_sql_instances: list[dict[str, Any]] = []
    vpc_networks: list[dict[str, Any]] = []
    disks: list[dict[str, Any]] = []
    pubsub_topics: list[dict[str, Any]] = []

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
    if include_containers:
        gke_clusters = _discover_gke_clusters(resolved_project, credentials=credentials, warnings=warnings)
    if include_serverless:
        cloud_run_services = _discover_cloud_run_services(resolved_project, credentials=credentials, warnings=warnings)
        cloud_functions = _discover_cloud_functions(resolved_project, credentials=credentials, warnings=warnings)
    if include_databases:
        cloud_sql_instances = _discover_cloud_sql_instances(resolved_project, credentials=credentials, warnings=warnings)
    if include_networks:
        vpc_networks = _discover_vpc_networks(resolved_project, credentials=credentials, warnings=warnings)
    if include_disks:
        disks = _discover_disks(resolved_project, credentials=credentials, warnings=warnings)
    if include_messaging:
        pubsub_topics = _discover_pubsub_topics(resolved_project, credentials=credentials, warnings=warnings)

    permissions_used: list[str] = []
    if include_storage:
        permissions_used.extend(_GCP_STORAGE_PERMISSIONS)
    if include_compute:
        permissions_used.extend(_GCP_COMPUTE_PERMISSIONS)
    if include_iam:
        permissions_used.extend(_GCP_IAM_PERMISSIONS)
    if include_containers:
        permissions_used.append("container.clusters.list")
    if include_serverless:
        permissions_used.extend(("run.services.list", "cloudfunctions.functions.list"))
    if include_databases:
        permissions_used.append("cloudsql.instances.list")
    if include_networks:
        permissions_used.extend(("compute.networks.list", "compute.subnetworks.list"))
    if include_disks:
        permissions_used.append("compute.disks.list")
    if include_messaging:
        permissions_used.append("pubsub.topics.list")

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
        "gke_clusters": gke_clusters,
        "cloud_run_services": cloud_run_services,
        "cloud_functions": cloud_functions,
        "cloud_sql_instances": cloud_sql_instances,
        "vpc_networks": vpc_networks,
        "disks": disks,
        "pubsub_topics": pubsub_topics,
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
# GKE clusters (container_v1, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


def _discover_gke_clusters(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every GKE cluster in the project (read-only).

    Uses the ``-`` location wildcard so a single call returns clusters across all
    regions/zones. A cluster with a public control-plane endpoint (no
    ``private_cluster_config.enable_private_endpoint``) is marked
    ``internet_exposed`` so the CNAPP / attack-path overlays treat it as an entry.
    """
    try:
        from google.cloud import container_v1
    except ImportError:
        warnings.append("google-cloud-container not installed. Skipping GKE cluster inventory.")
        return []

    clusters: list[dict[str, Any]] = []
    try:
        client = container_v1.ClusterManagerClient(credentials=credentials)
        response = client.list_clusters(parent=f"projects/{project_id}/locations/-")
        for cluster in getattr(response, "clusters", None) or []:
            name = str(getattr(cluster, "name", "") or "").strip()
            if not name:
                continue
            private_cfg = getattr(cluster, "private_cluster_config", None)
            private_endpoint = bool(getattr(private_cfg, "enable_private_endpoint", False)) if private_cfg else False
            clusters.append(
                {
                    "name": name,
                    "id": str(getattr(cluster, "id", "") or "") or name,
                    "location": str(getattr(cluster, "location", "") or ""),
                    "endpoint": str(getattr(cluster, "endpoint", "") or ""),
                    "private_cluster": bool(getattr(private_cfg, "enable_private_nodes", False)) if private_cfg else False,
                    "internet_exposed": not private_endpoint,
                    "node_count": _safe_int(str(getattr(cluster, "current_node_count", "") or "")) or 0,
                    "version": str(getattr(cluster, "current_master_version", "") or ""),
                    "labels": _clean_labels(getattr(cluster, "resource_labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — API-disabled / access-denied must degrade
        warnings.append(f"Could not list GKE clusters: {sanitize_discovery_warning(exc)}")
    return clusters


# ---------------------------------------------------------------------------
# Cloud Run services (run_v2, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


def _discover_cloud_run_services(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Cloud Run service in the project (read-only).

    Ingress ``INGRESS_TRAFFIC_ALL`` means the service is reachable from the
    internet → ``internet_exposed``. ``INGRESS_TRAFFIC_INTERNAL_*`` is private.
    """
    try:
        from google.cloud import run_v2
    except ImportError:
        warnings.append("google-cloud-run not installed. Skipping Cloud Run service inventory.")
        return []

    services: list[dict[str, Any]] = []
    try:
        client = run_v2.ServicesClient(credentials=credentials)
        request = run_v2.ListServicesRequest(parent=f"projects/{project_id}/locations/-")
        for service in client.list_services(request=request):
            full_name = str(getattr(service, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            ingress = str(getattr(service, "ingress", "") or "")
            region = _segment(full_name, "locations")
            services.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": region,
                    "url": str(getattr(service, "uri", "") or ""),
                    "ingress": ingress,
                    "internet_exposed": "ALL" in ingress.upper(),
                    "labels": _clean_labels(getattr(service, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Cloud Run services: {sanitize_discovery_warning(exc)}")
    return services


# ---------------------------------------------------------------------------
# Cloud Functions (functions_v2, project-wide via the "-" location wildcard)
# ---------------------------------------------------------------------------


def _discover_cloud_functions(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every 2nd-gen Cloud Function in the project (read-only)."""
    try:
        from google.cloud import functions_v2
    except ImportError:
        warnings.append("google-cloud-functions not installed. Skipping Cloud Functions inventory.")
        return []

    functions: list[dict[str, Any]] = []
    try:
        client = functions_v2.FunctionServiceClient(credentials=credentials)
        request = functions_v2.ListFunctionsRequest(parent=f"projects/{project_id}/locations/-")
        for function in client.list_functions(request=request):
            full_name = str(getattr(function, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            service_config = getattr(function, "service_config", None)
            ingress = str(getattr(service_config, "ingress_settings", "") or "") if service_config else ""
            event_trigger = getattr(function, "event_trigger", None)
            trigger = "event" if event_trigger else "https"
            functions.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": _segment(full_name, "locations"),
                    "trigger": trigger,
                    "ingress": ingress,
                    "internet_exposed": "ALL" in ingress.upper(),
                    "labels": _clean_labels(getattr(function, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Cloud Functions: {sanitize_discovery_warning(exc)}")
    return functions


# ---------------------------------------------------------------------------
# Cloud SQL instances (Admin API via google-api-python-client)
# ---------------------------------------------------------------------------


def _discover_cloud_sql_instances(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Cloud SQL instance in the project (read-only).

    The Cloud SQL Admin API has no idiomatic google-cloud client, so this uses
    the discovery-built ``sqladmin`` client. An instance with a public IPv4
    address (``PRIMARY`` ip_address) or an open authorized-network
    (``0.0.0.0/0``) is marked ``internet_exposed`` so a public managed database
    feeds the CNAPP / attack-path overlays.
    """
    try:
        from googleapiclient.discovery import build
    except ImportError:
        warnings.append("google-api-python-client not installed. Skipping Cloud SQL inventory.")
        return []

    instances: list[dict[str, Any]] = []
    try:
        service = build("sqladmin", "v1beta4", credentials=credentials, cache_discovery=False)
        response = service.instances().list(project=project_id).execute()
        for item in response.get("items", []) or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name", "") or "").strip()
            if not name:
                continue
            ip_addresses = [str(ip.get("ipAddress", "")) for ip in (item.get("ipAddresses") or []) if isinstance(ip, dict)]
            settings = item.get("settings") or {}
            ip_config = settings.get("ipConfiguration") or {}
            authorized = [str(net.get("value", "")) for net in (ip_config.get("authorizedNetworks") or []) if isinstance(net, dict)]
            public_ip = bool(ip_config.get("ipv4Enabled")) and bool(ip_addresses)
            open_network = any(net in _INTERNET_RANGES for net in authorized)
            disk_encryption = item.get("diskEncryptionConfiguration") or {}
            instances.append(
                {
                    "name": name,
                    "id": str(item.get("selfLink", "") or "") or name,
                    "location": str(item.get("region", "") or ""),
                    "database_version": str(item.get("databaseVersion", "") or ""),
                    "ip_addresses": ip_addresses,
                    "authorized_networks": authorized,
                    "publicly_accessible": public_ip or open_network,
                    "internet_exposed": public_ip or open_network,
                    "encrypted": bool(disk_encryption.get("kmsKeyName")),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001 — API-disabled / access-denied must degrade
        warnings.append(f"Could not list Cloud SQL instances: {sanitize_discovery_warning(exc)}")
    return instances


# ---------------------------------------------------------------------------
# VPC networks + subnets (compute_v1)
# ---------------------------------------------------------------------------


def _discover_vpc_networks(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every VPC network + its subnets in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping VPC network inventory.")
        return []

    subnets_by_network = _discover_subnets_by_network(project_id, credentials=credentials, warnings=warnings)
    networks: list[dict[str, Any]] = []
    try:
        client = compute_v1.NetworksClient(credentials=credentials)
        for network in client.list(project=project_id):
            name = str(getattr(network, "name", "") or "").strip()
            if not name:
                continue
            self_link = str(getattr(network, "self_link", "") or "")
            network_subnets = subnets_by_network.get(self_link, []) or subnets_by_network.get(name, [])
            networks.append(
                {
                    "name": name,
                    "id": str(getattr(network, "id", "") or "") or name,
                    "location": "global",
                    "auto_create_subnetworks": bool(getattr(network, "auto_create_subnetworks", False)),
                    "subnets": network_subnets,
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list VPC networks: {sanitize_discovery_warning(exc)}")
    return networks


def _discover_subnets_by_network(project_id: str, *, credentials: Any, warnings: list[str]) -> dict[str, list[dict[str, Any]]]:
    """Aggregated subnet list, keyed by the parent network self-link AND name."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        return {}

    by_network: dict[str, list[dict[str, Any]]] = {}
    try:
        client = compute_v1.SubnetworksClient(credentials=credentials)
        for _region, scoped_list in client.aggregated_list(project=project_id):
            for subnet in getattr(scoped_list, "subnetworks", None) or []:
                network_link = str(getattr(subnet, "network", "") or "")
                flow_logs = getattr(subnet, "enable_flow_logs", None)
                entry = {
                    "name": str(getattr(subnet, "name", "") or ""),
                    "region": _leaf(getattr(subnet, "region", "")),
                    "cidr": str(getattr(subnet, "ip_cidr_range", "") or ""),
                    "flow_logs": bool(flow_logs) if flow_logs is not None else False,
                }
                by_network.setdefault(network_link, []).append(entry)
                by_network.setdefault(_leaf(network_link), []).append(entry)
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list VPC subnets: {sanitize_discovery_warning(exc)}")
    return by_network


# ---------------------------------------------------------------------------
# Persistent disks (compute_v1, aggregated)
# ---------------------------------------------------------------------------


def _discover_disks(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every persistent disk in the project (read-only)."""
    try:
        from google.cloud import compute_v1
    except ImportError:
        warnings.append("google-cloud-compute not installed. Skipping persistent-disk inventory.")
        return []

    disks: list[dict[str, Any]] = []
    try:
        client = compute_v1.DisksClient(credentials=credentials)
        for _zone, scoped_list in client.aggregated_list(project=project_id):
            for disk in getattr(scoped_list, "disks", None) or []:
                name = str(getattr(disk, "name", "") or "").strip()
                if not name:
                    continue
                encryption = getattr(disk, "disk_encryption_key", None)
                disks.append(
                    {
                        "name": name,
                        "id": str(getattr(disk, "id", "") or "") or name,
                        "location": _leaf(getattr(disk, "zone", "")),
                        "size_gb": _safe_int(str(getattr(disk, "size_gb", "") or "")) or 0,
                        "encrypted": bool(getattr(encryption, "kms_key_name", "") if encryption else False),
                        "source_image": _leaf(getattr(disk, "source_image", "")),
                        "labels": _clean_labels(getattr(disk, "labels", None)),
                        "project_id": project_id,
                    }
                )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list persistent disks: {sanitize_discovery_warning(exc)}")
    return disks


# ---------------------------------------------------------------------------
# Pub/Sub topics (pubsub_v1)
# ---------------------------------------------------------------------------


def _discover_pubsub_topics(project_id: str, *, credentials: Any, warnings: list[str]) -> list[dict[str, Any]]:
    """Enumerate every Pub/Sub topic in the project (read-only)."""
    try:
        from google.cloud import pubsub_v1
    except ImportError:
        warnings.append("google-cloud-pubsub not installed. Skipping Pub/Sub topic inventory.")
        return []

    topics: list[dict[str, Any]] = []
    try:
        client = pubsub_v1.PublisherClient(credentials=credentials)
        for topic in client.list_topics(request={"project": f"projects/{project_id}"}):
            full_name = str(getattr(topic, "name", "") or "").strip()
            name = _leaf(full_name)
            if not name:
                continue
            topics.append(
                {
                    "name": name,
                    "id": full_name or name,
                    "location": "global",
                    "labels": _clean_labels(getattr(topic, "labels", None)),
                    "project_id": project_id,
                }
            )
    except Exception as exc:  # noqa: BLE001
        warnings.append(f"Could not list Pub/Sub topics: {sanitize_discovery_warning(exc)}")
    return topics


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _segment(self_link: str, key: str) -> str:
    """Return the path segment following ``key`` in a GCP resource name, else ''.

    e.g. ``_segment("projects/p/locations/us-central1/services/svc", "locations")``
    → ``"us-central1"``.
    """
    parts = str(self_link or "").split("/")
    for i, part in enumerate(parts):
        if part == key and i + 1 < len(parts):
            return parts[i + 1]
    return ""


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
    "ALL_PROJECTS_ENV_FLAG",
    "INVENTORY_ENV_FLAG",
    "all_projects_enabled",
    "discover_all_project_inventories",
    "discover_inventory",
    "inventory_enabled",
]
