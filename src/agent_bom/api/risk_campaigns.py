"""Derive explainable remediation campaigns from the canonical findings spine."""

from __future__ import annotations

import hashlib
import math
from collections import defaultdict
from typing import Any, Mapping

from agent_bom.api.campaign_store import CampaignWorkflow

_SEVERITY_SCORE = {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 1.5, "info": 0.5}


def _finding_id(row: Mapping[str, Any]) -> str:
    return str(row.get("id") or row.get("canonical_id") or row.get("finding_id") or row.get("vulnerability_id") or "").strip()


def _risk(row: Mapping[str, Any]) -> float:
    try:
        explicit = row.get("risk_score")
        if explicit is not None and not isinstance(explicit, bool):
            parsed = float(explicit)
            if math.isfinite(parsed):
                return round(min(10.0, max(0.0, parsed)), 1)
    except (TypeError, ValueError):
        pass
    return _SEVERITY_SCORE.get(str(row.get("severity") or "").lower(), 0.5)


def _group_key(row: Mapping[str, Any]) -> str:
    purl = _canonical_purl(str(row.get("purl") or ""))
    package = str(row.get("package") or row.get("component") or "").strip().lower()
    ecosystem = str(row.get("ecosystem") or "unknown").strip().lower()
    fixed = str(row.get("fixed_version") or "").strip().lower()
    if purl and fixed:
        return f"upgrade:purl:{purl}:{fixed}"
    if package and fixed:
        return f"upgrade:package:{ecosystem}:{package}:{fixed}"
    return f"finding:{_finding_id(row)}"


def _canonical_purl(value: str) -> str:
    """Return the package identity portion of a purl, excluding installation detail."""
    purl = value.strip().lower().split("#", 1)[0].split("?", 1)[0]
    if not purl.startswith("pkg:"):
        return purl
    head, separator, name = purl.rpartition("/")
    if not separator:
        head, name = "pkg:", purl[4:]
    name = name.rsplit("@", 1)[0]
    return f"{head}{separator}{name}" if separator else f"{head}{name}"


def _campaign_id(group_key: str) -> str:
    return f"campaign-{hashlib.sha256(group_key.encode('utf-8')).hexdigest()[:16]}"


def _asset_value(row: Mapping[str, Any], key: str) -> str:
    asset = row.get("asset")
    if isinstance(asset, Mapping):
        return str(asset.get(key) or "").strip()
    return ""


def _common_value(rows: list[dict[str, Any]], key: str) -> str | None:
    values = {_asset_value(row, key) or str(row.get(key) or "").strip() for row in rows}
    values.discard("")
    return next(iter(values)) if len(values) == 1 else None


def _factor_status(value: Any, *, observed: bool = False) -> dict[str, Any]:
    if value is None or value == "":
        return {"value": None, "status": "unknown"}
    return {"value": value, "status": "observed" if observed else "modeled"}


def _observed_bool(rows: list[dict[str, Any]], *keys: str) -> tuple[bool | None, list[str]]:
    values: list[bool] = []
    signals: list[str] = []
    for row in rows:
        for key in keys:
            value = row.get(key)
            if isinstance(value, bool):
                values.append(value)
                signals.append(key)
        symbol = str(row.get("symbol_reachability") or "").lower()
        if "symbol_reachability" in keys and symbol in {"function_reachable", "package_reachable", "unreachable"}:
            values.append(symbol != "unreachable")
            signals.append("symbol_reachability")
        if "reachable_functions" in keys and isinstance(row.get("reachable_functions"), list):
            values.append(bool(row["reachable_functions"]))
            signals.append("reachable_functions")
    return (any(values), sorted(set(signals))) if values else (None, [])


def _crown_jewel(rows: list[dict[str, Any]]) -> tuple[bool | None, list[str]]:
    observed: list[bool] = []
    signals: list[str] = []
    for row in rows:
        asset_value = row.get("asset")
        asset: Mapping[str, Any] = asset_value if isinstance(asset_value, Mapping) else {}
        for source, value in (("crown_jewel", row.get("crown_jewel")), ("asset.crown_jewel", asset.get("crown_jewel"))):
            if isinstance(value, bool):
                observed.append(value)
                signals.append(source)
        for source, value in (
            ("business_criticality", row.get("business_criticality")),
            ("asset.business_criticality", asset.get("business_criticality")),
            ("asset.criticality", asset.get("criticality")),
        ):
            normalized = str(value or "").strip().lower()
            if normalized in {"critical", "high", "medium", "low"}:
                observed.append(normalized in {"critical", "high"})
                signals.append(source)
    return (any(observed), sorted(set(signals))) if observed else (None, [])


def derive_campaigns(
    findings: list[dict[str, Any]],
    *,
    tenant_id: str,
    workflow_by_id: Mapping[str, CampaignWorkflow],
    window_days: int = 90,
    finding_limit: int = 1000,
    truncated: bool = False,
) -> list[dict[str, Any]]:
    """Group findings only when they share an explicit remediation target."""
    by_id: dict[str, dict[str, Any]] = {}
    for row in findings:
        if isinstance(row, dict) and (identity := _finding_id(row)):
            incumbent = by_id.get(identity)
            if incumbent is None or _risk(row) > _risk(incumbent):
                by_id[identity] = row
    usable = list(by_id.values())
    total_modeled_risk = sum(_risk(row) for row in usable)
    groups: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in usable:
        groups[_group_key(row)].append(row)

    campaigns: list[dict[str, Any]] = []
    for group_key, rows in groups.items():
        rows.sort(key=lambda row: _finding_id(row))
        campaign_id = _campaign_id(group_key)
        membership_fingerprint = hashlib.sha256("\x1f".join(_finding_id(row) for row in rows).encode()).hexdigest()
        workflow = workflow_by_id.get(campaign_id)
        highest = max(rows, key=_risk)
        base_risk = _risk(highest)
        campaign_risk = sum(_risk(row) for row in rows)
        severities = [str(row.get("severity") or "unknown").lower() for row in rows]
        severity = str(highest.get("severity") or "unknown").lower()
        kev = any(row.get("is_kev") is True or row.get("cisa_kev") is True for row in rows)
        epss = [
            float(row["epss_score"])
            for row in rows
            if isinstance(row.get("epss_score"), (int, float))
            and not isinstance(row.get("epss_score"), bool)
            and math.isfinite(float(row["epss_score"]))
            and 0.0 <= float(row["epss_score"]) <= 1.0
        ]
        reachable, reachability_signals = _observed_bool(
            rows, "is_reachable", "graph_reachable", "symbol_reachability", "reachable_functions"
        )
        crown_jewel, crown_signals = _crown_jewel(rows)
        business_context = _common_value(rows, "business_context")
        derived_owner = _common_value(rows, "owner")
        package = str(highest.get("package") or highest.get("component") or "").strip()
        fixed = str(highest.get("fixed_version") or "").strip()
        title = f"Upgrade {package} to {fixed}" if package and fixed else f"Remediate {_finding_id(highest)}"
        exploitability: dict[str, Any] = (
            {"value": "known_exploited", "status": "observed", "signals": ["kev"]}
            if kev
            else ({"value": max(epss), "status": "modeled", "signals": ["epss"]} if epss else _factor_status(None))
        )
        exploitability_boost = 1.0 if kev else (max(epss) if epss else 0.0)
        reachability_boost = 0.5 if reachable is True else 0.0
        crown_jewel_boost = 0.5 if crown_jewel is True else 0.0
        priority = round(min(10.0, base_risk + exploitability_boost + reachability_boost + crown_jewel_boost), 2)
        campaigns.append(
            {
                "id": campaign_id,
                "tenant_id": tenant_id,
                "title": title,
                "finding_ids": [_finding_id(row) for row in rows],
                "finding_count": len(rows),
                "severity": severity,
                "priority_score": priority,
                "priority_score_method": (
                    "min(10, max base finding risk + KEV 1.0 or max EPSS×1.0 + observed reachability 0.5 "
                    "+ explicit crown-jewel/high-criticality 0.5); unknown signals contribute 0"
                ),
                "priority_score_components": {
                    "base_finding_risk": base_risk,
                    "exploitability_boost": round(exploitability_boost, 2),
                    "reachability_boost": reachability_boost,
                    "crown_jewel_boost": crown_jewel_boost,
                    "cap": 10.0,
                },
                "score_factors": {
                    "severity": {"value": severity, "status": "observed", "bands_present": sorted(set(severities))},
                    "exploitability": exploitability,
                    "reachability": {
                        **_factor_status(reachable, observed=reachable is not None),
                        "signals": reachability_signals,
                    },
                    "business_context": _factor_status(business_context, observed=business_context is not None),
                    "crown_jewel": {
                        **_factor_status(crown_jewel, observed=crown_jewel is not None),
                        "signals": crown_signals,
                    },
                },
                "expected_risk_reduction": {
                    "modeled_window_percent": round((campaign_risk / total_modeled_risk) * 100, 1) if total_modeled_risk else 0.0,
                    "modeled_risk_points": round(campaign_risk, 1),
                    "assumption": "all campaign findings are remediated and verified",
                    "method": "campaign modeled risk divided by modeled risk in the bounded findings window",
                    "scope": f"last {window_days} days, first {finding_limit} findings",
                    "portfolio_complete": not truncated,
                },
                "owner": workflow.owner if workflow and workflow.owner is not None else derived_owner,
                "sla_due_at": workflow.sla_due_at if workflow else None,
                "state": workflow.state if workflow else "open",
                "verification_status": workflow.verification_status if workflow else "unverified",
                "updated_at": workflow.updated_at if workflow else None,
                "membership_fingerprint": membership_fingerprint,
                "generation": workflow.generation if workflow else 1,
                "active": workflow.active if workflow else True,
                "version": workflow.version if workflow else 1,
                "source": "canonical_findings_spine",
            }
        )
    campaigns.sort(key=lambda item: (-float(item["priority_score"]), -int(item["finding_count"]), str(item["id"])))
    return campaigns
