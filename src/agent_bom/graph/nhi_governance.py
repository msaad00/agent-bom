"""Non-human-identity (NHI) governance analytics over the unified graph.

The discovery (:mod:`agent_bom.graph.nhi_overlay`), governance
(:mod:`agent_bom.graph.governance_overlay`), and effective-permissions
(:mod:`agent_bom.graph.effective_permissions`) overlays place
``managed_identity`` nodes, ``HAS_PERMISSION`` / ``SCOPED_TO`` edges, and
privilege flags into one graph. This module is pure *analytics over that data* —
the three Natoma-parity capabilities that close the 2026-06-19 audit gap:

1. **Usage-based right-sizing.** Diff the permissions an identity is *granted*
   (the ``HAS_PERMISSION`` transitive closure + standing ``SCOPED_TO`` tool
   bindings) against what it is *observed* to use. Observed usage comes from a
   caller-passed usage map (``{identity_id: {permission targets used}}``) and/or
   per-target ``last_used_at`` telemetry on the edges, so it is testable without
   a live telemetry source. Granted-but-never-used targets are over-grants.

2. **Orphaned / dormant identity detection.** An identity with no recorded owner
   is *orphaned*; one whose ``last_used_at`` is older than
   ``AGENT_BOM_NHI_DORMANT_DAYS`` (default 90) — or which has no usage timestamp
   at all — is *dormant*. Both are standing, unattended attack surface.

3. **Per-identity risk score (0-100).** A single sortable score aggregating
   privilege level (admin / escalation), internet-exposure reachability,
   credential staleness (reusing :mod:`agent_bom.api.credential_expiry`), and
   dormancy. The score is written back onto the ``managed_identity`` node so the
   graph, API, and findings all rank the same way.

Reference-only: consumes labels, timestamps, and edge metadata already in the
graph; never touches secret material and never raises into the builder.
"""

from __future__ import annotations

import os
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.credential_expiry import classify_credential
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType

_OVERLAY_SOURCE = "nhi-governance"

DEFAULT_DORMANT_DAYS = 90

# Permission/scope edges that count as a *granted* capability for right-sizing.
_GRANT_RELS = frozenset({RelationshipType.HAS_PERMISSION, RelationshipType.SCOPED_TO})

# Credential states (from credential_expiry) that contribute staleness risk,
# mapped to the fraction of the staleness sub-score they carry.
_STALENESS_WEIGHT: dict[str, float] = {
    "expired": 1.0,
    "overdue": 1.0,
    "rotation_due": 0.7,
    "near_expiry": 0.5,
    "unknown_age": 0.3,
    "ok": 0.0,
}

# Risk sub-score weights (sum to 100). Privilege and exposure dominate because a
# dormant low-privilege identity is far less dangerous than a live admin one.
_W_PRIVILEGE = 35.0
_W_EXPOSURE = 25.0
_W_STALENESS = 20.0
_W_DORMANCY = 12.0
_W_ORPHAN = 8.0

_MAX_IDENTITIES = 5000


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        parsed = int(raw)
    except ValueError:
        return default
    return parsed if parsed >= 0 else default


def dormant_days() -> int:
    """Configured dormancy window in days (default 90)."""
    return _env_int("AGENT_BOM_NHI_DORMANT_DAYS", DEFAULT_DORMANT_DAYS)


def _parse_timestamp(raw: Any) -> datetime | None:
    if not isinstance(raw, str):
        return None
    text = raw.strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _days_since(ts: datetime, now: datetime) -> int:
    return int((now - ts).total_seconds() // 86400)


@dataclass
class IdentityGovernance:
    """Per-identity governance verdict (non-secret, JSON-serializable)."""

    node_id: str
    identity_id: str
    name: str
    provider: str | None
    owner: str | None
    risk_score: int
    risk_band: str
    granted_count: int
    used_count: int
    unused_targets: list[str] = field(default_factory=list)
    is_orphaned: bool = False
    is_dormant: bool = False
    dormant_days: int | None = None
    last_used_at: str | None = None
    credential_state: str | None = None
    is_privileged: bool = False
    can_escalate: bool = False
    internet_exposed: bool = False
    risk_factors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "identity_id": self.identity_id,
            "name": self.name,
            "provider": self.provider,
            "owner": self.owner,
            "risk_score": self.risk_score,
            "risk_band": self.risk_band,
            "granted_count": self.granted_count,
            "used_count": self.used_count,
            "unused_permission_count": len(self.unused_targets),
            "unused_targets": list(self.unused_targets),
            "is_orphaned": self.is_orphaned,
            "is_dormant": self.is_dormant,
            "dormant_days": self.dormant_days,
            "last_used_at": self.last_used_at,
            "credential_state": self.credential_state,
            "is_privileged": self.is_privileged,
            "can_escalate": self.can_escalate,
            "internet_exposed": self.internet_exposed,
            "risk_factors": list(self.risk_factors),
        }


def _risk_band(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def _granted_targets(graph: UnifiedGraph, node_id: str) -> dict[str, str | None]:
    """Return {granted target id: last_used_at on the edge (or None)}."""
    granted: dict[str, str | None] = {}
    for edge in graph.edges:
        if edge.source != node_id or edge.relationship not in _GRANT_RELS:
            continue
        last_used = None
        if isinstance(edge.evidence, Mapping):
            raw = edge.evidence.get("last_used_at")
            last_used = str(raw) if isinstance(raw, str) and raw.strip() else None
        # An earlier edge to the same target with a usage timestamp wins.
        if edge.target not in granted or (last_used and not granted[edge.target]):
            granted[edge.target] = last_used
    return granted


def _exposed_targets(graph: UnifiedGraph, targets: set[str]) -> bool:
    return any(graph.nodes.get(tid) is not None and bool(graph.nodes[tid].attributes.get("internet_exposed")) for tid in targets)


def evaluate_identity_governance(
    graph: UnifiedGraph,
    *,
    usage: Mapping[str, set[str]] | Mapping[str, list[str]] | None = None,
    dormant_after_days: int | None = None,
    now: datetime | None = None,
) -> list[IdentityGovernance]:
    """Compute the per-identity governance verdict for every NHI in the graph.

    ``usage`` maps an identity id (or node id) to the set of permission targets
    it was *observed* to use. When omitted, observed usage falls back to any
    ``last_used_at`` markers on the grant edges; a grant with neither is treated
    as unused for right-sizing. Never raises.
    """
    now = now or datetime.now(timezone.utc)
    window = dormant_after_days if dormant_after_days is not None else dormant_days()
    usage_map: dict[str, set[str]] = {}
    if usage:
        for key, vals in usage.items():
            usage_map[str(key)] = {str(v) for v in vals}

    identities = [n for n in graph.nodes.values() if n.entity_type == EntityType.MANAGED_IDENTITY]
    results: list[IdentityGovernance] = []
    for node in identities[:_MAX_IDENTITIES]:
        attrs = node.attributes
        identity_id = str(attrs.get("identity_id") or node.id)
        owner = attrs.get("owner")
        owner_str = str(owner).strip() if isinstance(owner, str) and str(owner).strip() else None

        granted = _granted_targets(graph, node.id)
        observed = set(usage_map.get(identity_id, set())) | set(usage_map.get(node.id, set()))
        # Edge-level last_used markers count as observed usage for that target.
        observed |= {tid for tid, last_used in granted.items() if last_used}
        unused = sorted(tid for tid in granted if tid not in observed)

        # ── Dormancy ──
        last_used_at = attrs.get("last_used_at")
        last_used_dt = _parse_timestamp(last_used_at)
        dormancy_days: int | None = None
        if last_used_dt is not None:
            dormancy_days = max(0, _days_since(last_used_dt, now))
            is_dormant = dormancy_days >= window
        else:
            # No usage timestamp at all → treat as dormant (never-observed).
            is_dormant = True
        is_orphaned = owner_str is None

        # ── Privilege / exposure ──
        is_privileged = bool(attrs.get("escalates_to_admin") or attrs.get("is_admin") or attrs.get("privilege_level") == "admin")
        can_escalate = bool(attrs.get("can_escalate_privilege"))
        internet_exposed = bool(attrs.get("internet_exposed")) or _exposed_targets(graph, set(granted))

        # ── Credential staleness (reuse credential_expiry classifier) ──
        cred_state = classify_credential(
            {
                "id": identity_id,
                "name": node.label,
                "provider": attrs.get("provider"),
                "credential_expires_at": attrs.get("credential_expires_at"),
                "last_rotated": attrs.get("last_rotated") or attrs.get("created_at"),
            },
            now=now,
        )["state"]

        # ── Aggregate 0-100 risk score ──
        privilege_factor = 1.0 if is_privileged else (0.6 if can_escalate else 0.0)
        exposure_factor = 1.0 if internet_exposed else 0.0
        staleness_factor = _STALENESS_WEIGHT.get(cred_state, 0.0)
        dormancy_factor = 0.0
        if is_dormant:
            if dormancy_days is None:
                dormancy_factor = 1.0
            else:
                dormancy_factor = min(1.0, dormancy_days / max(window, 1))
        orphan_factor = 1.0 if is_orphaned else 0.0

        score = (
            _W_PRIVILEGE * privilege_factor
            + _W_EXPOSURE * exposure_factor
            + _W_STALENESS * staleness_factor
            + _W_DORMANCY * dormancy_factor
            + _W_ORPHAN * orphan_factor
        )
        risk_score = int(round(min(100.0, score)))

        factors: list[str] = []
        if is_privileged:
            factors.append("admin/privileged")
        elif can_escalate:
            factors.append("can escalate privilege")
        if internet_exposed:
            factors.append("reaches internet-exposed resource")
        if staleness_factor > 0:
            factors.append(f"credential {cred_state}")
        if is_dormant:
            factors.append("dormant" if dormancy_days is None else f"dormant {dormancy_days}d")
        if is_orphaned:
            factors.append("no owner")
        if unused:
            factors.append(f"{len(unused)} unused permission(s)")

        results.append(
            IdentityGovernance(
                node_id=node.id,
                identity_id=identity_id,
                name=node.label,
                provider=attrs.get("provider") if isinstance(attrs.get("provider"), str) else None,
                owner=owner_str,
                risk_score=risk_score,
                risk_band=_risk_band(risk_score),
                granted_count=len(granted),
                used_count=len(observed & set(granted)),
                unused_targets=unused,
                is_orphaned=is_orphaned,
                is_dormant=is_dormant,
                dormant_days=dormancy_days,
                last_used_at=str(last_used_at) if isinstance(last_used_at, str) else None,
                credential_state=cred_state,
                is_privileged=is_privileged,
                can_escalate=can_escalate,
                internet_exposed=internet_exposed,
                risk_factors=factors,
            )
        )

    results.sort(key=lambda r: (-r.risk_score, r.name))
    return results


def _target_label(graph: UnifiedGraph, target_id: str) -> str:
    node = graph.nodes.get(target_id)
    return node.label if node is not None else target_id


def _severity_for_score(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def build_nhi_governance_findings(
    graph: UnifiedGraph,
    verdicts: list[IdentityGovernance],
) -> list[Finding]:
    """Materialize over-grant, dormant/orphaned, and high-risk findings.

    Reuses :data:`FindingType.CREDENTIAL_EXPOSURE` (the closest identity-credential
    governance category) so the findings flow through the existing unified stream.
    """
    findings: list[Finding] = []
    for v in verdicts:
        asset = Asset(name=v.name, asset_type="agent", identifier=v.identity_id, location=v.provider)

        # 1. Right-sizing — granted but never used.
        if v.unused_targets:
            labels = [_target_label(graph, tid) for tid in v.unused_targets[:20]]
            findings.append(
                Finding(
                    finding_type=FindingType.CREDENTIAL_EXPOSURE,
                    source=FindingSource.MCP_SCAN,
                    asset=asset,
                    severity="medium" if v.is_privileged else "low",
                    title=f"Over-granted identity: {v.name} has {len(v.unused_targets)} unused permission(s)",
                    description=(
                        f"Identity '{v.name}' is granted {v.granted_count} permission(s) but is observed using "
                        f"{v.used_count}. Right-size by removing the unused grants: {', '.join(labels)}"
                        + ("…" if len(v.unused_targets) > 20 else ".")
                    ),
                    remediation_guidance=("Remove the unused permissions / tool scopes from this identity to enforce least privilege."),
                    evidence={
                        "nhi_governance": "over_grant",
                        "identity_id": v.identity_id,
                        "granted_count": v.granted_count,
                        "used_count": v.used_count,
                        "unused_permission_count": len(v.unused_targets),
                        "unused_targets": labels,
                        "risk_score": v.risk_score,
                    },
                    risk_score=round(min(10.0, v.risk_score / 10.0), 2),
                )
            )

        # 2. Dormant / orphaned.
        if v.is_dormant or v.is_orphaned:
            reasons = []
            if v.is_dormant:
                reasons.append("dormant" if v.dormant_days is None else f"dormant for {v.dormant_days}d")
            if v.is_orphaned:
                reasons.append("no owner assigned")
            findings.append(
                Finding(
                    finding_type=FindingType.CREDENTIAL_EXPOSURE,
                    source=FindingSource.MCP_SCAN,
                    asset=asset,
                    severity="high" if (v.is_privileged or v.internet_exposed) else "medium",
                    title=f"Unattended non-human identity: {v.name} ({', '.join(reasons)})",
                    description=(
                        f"Identity '{v.name}' is {' and '.join(reasons)}. Standing unattended NHIs are a common "
                        "lateral-movement entry point and should be deprovisioned or re-owned."
                    ),
                    remediation_guidance=("Deprovision the identity if no longer needed, or assign an owner and confirm continued use."),
                    evidence={
                        "nhi_governance": "unattended_identity",
                        "identity_id": v.identity_id,
                        "is_dormant": v.is_dormant,
                        "is_orphaned": v.is_orphaned,
                        "dormant_days": v.dormant_days,
                        "last_used_at": v.last_used_at,
                        "risk_score": v.risk_score,
                    },
                    risk_score=round(min(10.0, v.risk_score / 10.0), 2),
                )
            )

    return findings


def apply_nhi_governance(
    graph: UnifiedGraph,
    *,
    usage: Mapping[str, set[str]] | Mapping[str, list[str]] | None = None,
    dormant_after_days: int | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Annotate ``managed_identity`` nodes with their risk score, in place.

    Computes the per-identity governance verdict, writes ``nhi_risk_score`` /
    ``nhi_risk_band`` / right-sizing / dormancy / orphan flags onto each node,
    and returns a non-secret summary plus the structured verdicts so callers can
    emit findings. Never raises into the builder.
    """
    try:
        verdicts = evaluate_identity_governance(graph, usage=usage, dormant_after_days=dormant_after_days, now=now)
    except Exception:  # noqa: BLE001 — never raise into the builder
        return {"identities": 0, "verdicts": [], "over_granted": 0, "dormant": 0, "orphaned": 0}

    over_granted = dormant = orphaned = 0
    for v in verdicts:
        node = graph.nodes.get(v.node_id)
        if node is None:
            continue
        node.attributes["nhi_risk_score"] = v.risk_score
        node.attributes["nhi_risk_band"] = v.risk_band
        node.attributes["nhi_unused_permission_count"] = len(v.unused_targets)
        node.attributes["nhi_is_dormant"] = v.is_dormant
        node.attributes["nhi_is_orphaned"] = v.is_orphaned
        if v.risk_factors:
            node.attributes["nhi_risk_factors"] = list(v.risk_factors)
        # Surface the score on the node's own risk_score (0-10) so default graph
        # ranking reflects it, without dropping the precise 0-100 attribute.
        node.risk_score = max(node.risk_score, round(v.risk_score / 10.0, 2))
        if v.unused_targets:
            over_granted += 1
        if v.is_dormant:
            dormant += 1
        if v.is_orphaned:
            orphaned += 1

    return {
        "identities": len(verdicts),
        "verdicts": verdicts,
        "over_granted": over_granted,
        "dormant": dormant,
        "orphaned": orphaned,
    }


def describe_nhi_governance_posture(
    graph: UnifiedGraph,
    *,
    usage: Mapping[str, set[str]] | Mapping[str, list[str]] | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Return the consolidated, non-secret NHI governance posture for an API surface.

    Mirrors the credential-expiry posture shape: a rolled-up status, per-identity
    verdicts (worst risk first), and grouped right-sizing / dormancy / orphan
    counts. Secret values are never included.
    """
    summary = apply_nhi_governance(graph, usage=usage, now=now)
    verdicts: list[IdentityGovernance] = summary["verdicts"]
    by_band: dict[str, int] = defaultdict(int)
    for v in verdicts:
        by_band[v.risk_band] += 1

    if by_band.get("critical"):
        status = "blocked"
        message = "One or more non-human identities carry critical standing risk."
    elif by_band.get("high") or summary["dormant"] or summary["orphaned"] or summary["over_granted"]:
        status = "attention_required"
        message = "Non-human identities are over-granted, dormant, orphaned, or high risk."
    else:
        status = "ok"
        message = "All evaluated non-human identities are within governance bounds."

    return {
        "status": status,
        "secret_values_included": False,
        "evaluated": len(verdicts),
        "dormant_after_days": dormant_days(),
        "counts": {
            "over_granted": summary["over_granted"],
            "dormant": summary["dormant"],
            "orphaned": summary["orphaned"],
            "by_risk_band": dict(by_band),
        },
        "identities": [v.to_dict() for v in verdicts],
        "message": message,
        "generated_from": "/v1/auth/nhi/governance",
    }


def apply_nhi_governance_with_findings(
    graph: UnifiedGraph,
    *,
    usage: Mapping[str, set[str]] | Mapping[str, list[str]] | None = None,
    dormant_after_days: int | None = None,
    now: datetime | None = None,
) -> tuple[dict[str, Any], list[Finding]]:
    """Annotate nodes and return ``(summary, findings)`` in one call.

    Convenience for the scan pipeline, which both enriches the graph and appends
    to the unified finding stream.
    """
    summary = apply_nhi_governance(graph, usage=usage, dormant_after_days=dormant_after_days, now=now)
    findings = build_nhi_governance_findings(graph, summary["verdicts"])
    return summary, findings


__all__ = [
    "DEFAULT_DORMANT_DAYS",
    "IdentityGovernance",
    "apply_nhi_governance",
    "apply_nhi_governance_with_findings",
    "build_nhi_governance_findings",
    "describe_nhi_governance_posture",
    "dormant_days",
    "evaluate_identity_governance",
]
