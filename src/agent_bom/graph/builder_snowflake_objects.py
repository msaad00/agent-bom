"""Snowflake object catalog, lineage, access layer and identity-threat projection."""

from __future__ import annotations

from typing import Any

from agent_bom.graph.cloud_context import _add_account_resource_hierarchy, _add_identity_node, _prepare_cloud_payload
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.projection_support import _add_rel_edge
from agent_bom.graph.types import EntityType, RelationshipType
from agent_bom.graph.util import clean_graph_part as _clean_graph_part


class _SnowflakeObjectGraph:
    """Per-payload projector for Snowflake objects, lineage and the CIEM access layer."""

    def __init__(self, graph: UnifiedGraph, account: str, data_sources: list[str]) -> None:
        self.graph = graph
        self.account = account
        self.data_sources = data_sources
        self.account_node_id = ""
        self.seen: set[str] = set()
        self.seen_roles: set[str] = set()
        self.seen_users: set[str] = set()
        if account:
            self.account_node_id = _add_identity_node(
                graph,
                EntityType.ACCOUNT,
                account,
                "snowflake",
                data_sources,
                label=account or "snowflake",
                account_id=account,
                cloud_provider="snowflake",
                source="snowflake-objects",
            )

    def ensure_object(self, fqn: str, *, object_type: str = "object", attributes: dict[str, Any] | None = None) -> str:
        node_id = f"data_store:snowflake:{fqn}"
        if node_id in self.seen:
            return node_id
        self.seen.add(node_id)
        self.graph.add_node(
            UnifiedNode(
                id=node_id,
                entity_type=EntityType.DATA_STORE,
                label=f"{object_type}: {fqn}",
                attributes={
                    "fqn": fqn,
                    "object_type": object_type,
                    "cloud_provider": "snowflake",
                    "is_data_store": True,
                    **(attributes or {}),
                },
                data_sources=self.data_sources,
                dimensions=NodeDimensions(cloud_provider="snowflake", surface="data"),
            )
        )
        if self.account_node_id:
            _add_account_resource_hierarchy(
                self.graph,
                self.account_node_id,
                node_id,
                evidence={"source": "snowflake-objects"},
            )
        return node_id

    def ensure_role(self, name: str) -> str:
        node_id = f"role:snowflake:{name}"
        if node_id not in self.seen_roles:
            self.seen_roles.add(node_id)
            _add_identity_node(
                self.graph,
                EntityType.ROLE,
                name,
                "snowflake",
                self.data_sources,
                label=f"role: {name}",
                role_name=name,
                cloud_provider="snowflake",
                source="snowflake-objects",
            )
        return node_id

    def ensure_user(self, user_name: str, **extra: Any) -> str:
        node_id = f"user:snowflake:{user_name}"
        if node_id not in self.seen_users:
            self.seen_users.add(node_id)
            _add_identity_node(
                self.graph,
                EntityType.USER,
                user_name,
                "snowflake",
                self.data_sources,
                label=f"user: {user_name}",
                user_name=user_name,
                cloud_provider="snowflake",
                source="snowflake-objects",
                **{k: v for k, v in extra.items() if v not in (None, "")},
            )
        return node_id

    def add_objects(self, objects: Any) -> None:
        for obj in objects or []:
            if not isinstance(obj, dict):
                continue
            fqn = _clean_graph_part(obj.get("fqn"))
            if not fqn:
                continue
            self.ensure_object(
                fqn,
                object_type=str(obj.get("object_type") or "object"),
                attributes={
                    "database": obj.get("database"),
                    "schema": obj.get("schema"),
                    "row_count": obj.get("row_count"),
                    "bytes": obj.get("bytes"),
                },
            )

    def add_dependencies(self, dependencies: Any) -> None:
        for dep in dependencies or []:
            if not isinstance(dep, dict):
                continue
            referencing = _clean_graph_part(dep.get("referencing_fqn"))
            referenced = _clean_graph_part(dep.get("referenced_fqn"))
            if not referencing or not referenced:
                continue
            # Dependency endpoints may not be in the objects list (e.g. SNOWFLAKE
            # system objects) — create thin nodes so the lineage edge still lands.
            src = self.ensure_object(referencing, object_type=str(dep.get("referencing_domain") or "object").lower())
            tgt = self.ensure_object(referenced, object_type=str(dep.get("referenced_domain") or "object").lower())
            _add_rel_edge(
                self.graph,
                src,
                tgt,
                RelationshipType.DEPENDS_ON,
                {"source": "snowflake-objects", "dependency_type": dep.get("dependency_type", "")},
            )

    def add_grants(self, grants: Any) -> None:
        """Object-level grants: role HAS_PERMISSION on the object (data store)."""
        for grant in grants or []:
            if not isinstance(grant, dict):
                continue
            role = _clean_graph_part(grant.get("role"))
            object_fqn = _clean_graph_part(grant.get("object_fqn"))
            if not role or not object_fqn:
                continue
            _add_rel_edge(
                self.graph,
                self.ensure_role(role),
                self.ensure_object(object_fqn, object_type=str(grant.get("object_type") or "object").lower()),
                RelationshipType.HAS_PERMISSION,
                {
                    "source": "snowflake-objects",
                    "privilege": grant.get("privilege", ""),
                    "grant_receipts": [
                        {
                            "source": "snowflake-objects",
                            "account": self.account or None,
                            "role": role,
                            "privilege": grant.get("privilege", ""),
                            "object_fqn": object_fqn,
                            "object_type": str(grant["object_type"]).lower() if grant.get("object_type") else None,
                        }
                    ],
                },
            )

    def add_users(self, users: Any) -> None:
        """Standalone users (no membership row yet) so new accounts graph instantly."""
        for usr in users or []:
            if not isinstance(usr, dict):
                continue
            user_name = _clean_graph_part(usr.get("name"))
            if not user_name:
                continue
            self.ensure_user(
                user_name,
                default_role=_clean_graph_part(usr.get("default_role")) or None,
                disabled=usr.get("disabled"),
            )

    def add_memberships(self, memberships: Any) -> None:
        for membership in memberships or []:
            if not isinstance(membership, dict):
                continue
            role = _clean_graph_part(membership.get("role"))
            if not role:
                continue
            parent = _clean_graph_part(membership.get("parent"))
            is_role_member = str(membership.get("member_type") or "").lower() == "role" or bool(parent)
            if is_role_member:
                # Role → role: the child role is a MEMBER_OF the parent and inherits
                # (ASSUMES) its privileges, so privilege chains traverse end-to-end.
                if not parent:
                    continue
                self._link_member(self.ensure_role(role), self.ensure_role(parent))
                continue
            # User → role: the user is a MEMBER_OF and ASSUMES the role's privileges.
            user_name = _clean_graph_part(membership.get("user"))
            if not user_name:
                continue
            user_node_id = self.ensure_user(user_name)
            self._link_member(user_node_id, self.ensure_role(role))

    def _link_member(self, member_id: str, role_id: str) -> None:
        _add_rel_edge(self.graph, member_id, role_id, RelationshipType.MEMBER_OF, {"source": "snowflake-objects"})
        _add_rel_edge(self.graph, member_id, role_id, RelationshipType.ASSUMES, {"source": "snowflake-objects"})


def _add_snowflake_object_graph(graph: UnifiedGraph, payload: Any, data_source: str) -> None:
    """Promote Snowflake tables/views + their lineage into the graph.

    Each table/view becomes a ``DATA_STORE`` node owned by the Snowflake
    account; ``OBJECT_DEPENDENCIES`` become ``DEPENDS_ON`` edges (the referencing
    object depends on the referenced one — e.g. a view on its base table). This
    is the data-lineage layer: blast-radius and exfil analysis can walk from a
    table to everything derived from it. Never raises; a missing/empty payload
    is a no-op.
    """
    prepared = _prepare_cloud_payload(payload, data_source, "snowflake-objects")
    if prepared is None:
        return
    account, data_sources = prepared
    projector = _SnowflakeObjectGraph(graph, account, data_sources)
    projector.add_objects(payload.get("objects", []))
    projector.add_dependencies(payload.get("dependencies", []))
    # Roles + users (CIEM access layer). ``role_memberships`` carry user→role
    # grants; the live SHOW overlay also emits role→role memberships
    # ({role, parent}) and a top-level ``users`` list.
    projector.add_grants(payload.get("grants", []))
    projector.add_users(payload.get("users", []))
    projector.add_memberships(payload.get("role_memberships", []))


def _enrich_snowflake_user(
    graph: UnifiedGraph, data_sources: list[str], name: str, attrs: dict[str, Any], *, severity: str | None, mitre: list[str]
) -> None:
    name = _clean_graph_part(name)
    if not name:
        return
    node = UnifiedNode(
        id=f"user:snowflake:{name}",
        entity_type=EntityType.USER,
        label=f"user: {name}",
        severity=severity or "",
        attributes={"user_name": name, "cloud_provider": "snowflake", **attrs},
        data_sources=data_sources,
        dimensions=NodeDimensions(cloud_provider="snowflake", surface="identity"),
        compliance_tags=sorted(set(mitre)),
    )
    graph.add_node(node)  # merges onto an existing user node (attrs/tags/severity union)


def _add_snowflake_login_threats(graph: UnifiedGraph, data_sources: list[str], login_payload: dict[str, Any]) -> None:
    rapid_by_user = {
        _clean_graph_part(it.get("user")): int(it.get("rapid_switches", 0) or 0)
        for it in login_payload.get("impossible_travel", []) or []
        if isinstance(it, dict)
    }
    failed_by_user = {
        _clean_graph_part(b.get("user")): int(b.get("failed", 0) or 0)
        for b in login_payload.get("failed_bursts", []) or []
        if isinstance(b, dict)
    }
    for u in login_payload.get("per_user", []) or []:
        if not isinstance(u, dict):
            continue
        name = _clean_graph_part(u.get("user"))
        if not name:
            continue
        impossible = name in rapid_by_user
        failed = failed_by_user.get(name, int(u.get("failed", 0) or 0))
        distinct_ips = int(u.get("distinct_ips", 0) or 0)
        mitre: list[str] = []
        sev = None
        if impossible:
            mitre.append("T1078")  # Valid Accounts
            sev = "high"
        if failed_by_user.get(name):
            mitre.append("T1110")  # Brute Force
            sev = sev or "medium"
        _enrich_snowflake_user(
            graph,
            data_sources,
            name,
            {
                "impossible_travel": impossible,
                "rapid_ip_switches": rapid_by_user.get(name, 0),
                "distinct_login_ips": distinct_ips,
                "failed_logins": failed,
                "identity_threat": bool(mitre),
            },
            severity=sev,
            mitre=mitre,
        )


def _add_snowflake_auth_posture(graph: UnifiedGraph, data_sources: list[str], auth_payload: dict[str, Any]) -> None:
    account_np = bool(auth_payload.get("account_network_policy"))
    for u in auth_payload.get("users", []) or []:
        if not isinstance(u, dict):
            continue
        name = _clean_graph_part(u.get("name"))
        if not name:
            continue
        auth_methods = list(u.get("auth_methods") or [])
        has_mfa = bool(u.get("has_mfa"))
        disabled = bool(u.get("disabled"))
        user_type = str(u.get("user_type", "") or "").upper()
        weak = not disabled and "password" in auth_methods and not has_mfa and user_type in ("PERSON", "UNKNOWN", "")
        _enrich_snowflake_user(
            graph,
            data_sources,
            name,
            {
                "auth_methods": auth_methods,
                "has_mfa": has_mfa,
                "disabled": disabled,
                "user_type": user_type or "unknown",
                "account_network_policy": account_np,
                "weak_auth": weak,
            },
            severity="high" if weak else None,
            mitre=["T1078"] if weak else [],  # Valid Accounts (weak credential control)
        )


def _add_snowflake_identity(graph: UnifiedGraph, login_payload: Any, auth_payload: Any, data_source: str) -> None:
    """Enrich Snowflake user nodes with identity-threat + auth-posture signal.

    Closes the gap where login-anomaly detection and auth-posture inventory
    reached JSON but never the graph, so a flagged/weak identity was invisible
    to the visual and blast-radius. For each affected user this merges threat +
    posture attributes onto the existing ``user:snowflake:<name>`` node (a thin
    node is created when the user appears only in the threat feed), tags the
    relevant **MITRE ATT&CK** technique, and raises node severity. Never raises;
    missing/empty/non-ok payloads are a no-op.

    Technique mapping:
      * impossible travel / high distinct-IP → ``T1078`` (Valid Accounts)
      * failed-login burst → ``T1110`` (Brute Force)
      * password user without MFA → ``T1078`` (Valid Accounts)
    """
    login_ok = isinstance(login_payload, dict) and login_payload.get("status") == "ok"
    auth_ok = isinstance(auth_payload, dict) and auth_payload.get("status") == "ok"
    if not login_ok and not auth_ok:
        return
    data_sources = sorted({data_source, "snowflake-identity"} - {""})
    if login_ok:
        _add_snowflake_login_threats(graph, data_sources, login_payload)
    if auth_ok:
        _add_snowflake_auth_posture(graph, data_sources, auth_payload)
