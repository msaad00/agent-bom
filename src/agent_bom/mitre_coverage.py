"""MITRE technique-coverage surface (#3892).

Aggregates a tenant's findings into an honest *coverage* view per adversary
framework: which techniques the estate's findings actually provide evidence
for, versus the full technique catalogue.

Honesty contract:

* **Covered** = a technique carries at least one finding with mapped evidence
  (an ATT&CK / ATLAS technique tag, or a MAESTRO layer derived from an
  explicitly mapped finding source).
* **Uncovered** = *no evidence yet*. It is **not** an assertion that the
  technique is mitigated or that the estate is safe against it. A big estate
  with few tagged findings honestly shows low coverage rather than a fabricated
  high number.

Denominators come straight from the active catalogues (ATT&CK / ATLAS) or the
fixed MAESTRO layer set, so ``coverage_pct`` reflects the real framework size.

This module is pure and side-effect free: callers pass in already-loaded
finding payloads (see :mod:`agent_bom.api.routes` for the tenant-scoped, off
the event loop wiring). It does no database or network I/O of its own.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

# Cap finding references per technique so the payload stays bounded even when a
# single technique is tagged by hundreds of thousands of findings at scale.
_MAX_REFS_PER_TECHNIQUE = 25

COVERED_DEFINITION = "technique has >=1 finding with mapped evidence"
UNCOVERED_DEFINITION = (
    "no finding evidence yet; this is 'no evidence', NOT an assertion that the "
    "technique is mitigated or that the estate is safe against it"
)

# Candidate finding fields that may carry ATT&CK technique tags, in priority
# order. Native scans emit ``attack_tags``; some ingest paths use
# ``attack_techniques``.
_ATTACK_TAG_FIELDS: tuple[str, ...] = ("attack_tags", "attack_techniques", "mitre_attack_tags")
_ATLAS_TAG_FIELDS: tuple[str, ...] = ("atlas_tags", "mitre_atlas_tags")


def _canonical_technique_id(raw: Any) -> str:
    """Normalize a raw technique tag to its canonical catalogue form."""
    text = str(raw or "").strip().upper()
    # Tags are sometimes rendered as "T1190 Exploit Public-Facing App"; keep the
    # leading identifier token only.
    return text.split()[0] if text else ""


def _finding_ref(finding: Mapping[str, Any]) -> str:
    for key in ("id", "finding_id", "canonical_id"):
        value = finding.get(key)
        if value:
            return str(value)
    return ""


def _iter_tags(finding: Mapping[str, Any], fields: tuple[str, ...]) -> Iterable[str]:
    for field in fields:
        raw = finding.get(field)
        if not raw:
            continue
        if isinstance(raw, str):
            yield raw
            continue
        if isinstance(raw, Iterable):
            for item in raw:
                if item:
                    yield str(item)


def _collect_technique_refs(
    findings: Iterable[Mapping[str, Any]],
    *,
    tag_fields: tuple[str, ...],
    valid_ids: Mapping[str, str],
) -> dict[str, list[str]]:
    """Map ``technique_id -> ordered, de-duplicated finding refs``.

    Only technique ids present in ``valid_ids`` are counted, so an unknown or
    malformed tag never inflates coverage.
    """
    refs: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        ref = _finding_ref(finding)
        for raw in _iter_tags(finding, tag_fields):
            tid = _canonical_technique_id(raw)
            if not tid or tid not in valid_ids:
                continue
            bucket = refs.setdefault(tid, [])
            seen_refs = seen.setdefault(tid, set())
            if ref and ref not in seen_refs:
                seen_refs.add(ref)
                bucket.append(ref)
    return refs


def _covered_techniques(
    refs: Mapping[str, list[str]],
    *,
    labels: Mapping[str, str],
    label_fn: Any = None,
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for tid in sorted(refs):
        ordered = refs[tid]
        label = label_fn(tid) if label_fn is not None else labels.get(tid, tid)
        out.append(
            {
                "id": tid,
                "label": label,
                "finding_count": len(ordered),
                "finding_refs": ordered[:_MAX_REFS_PER_TECHNIQUE],
                "finding_refs_truncated": len(ordered) > _MAX_REFS_PER_TECHNIQUE,
            }
        )
    return out


def _coverage_pct(covered: int, total: int) -> float:
    if total <= 0:
        return 0.0
    return round(covered / total * 100, 2)


def build_attack_coverage(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Coverage of MITRE ATT&CK Enterprise techniques by finding evidence."""
    from agent_bom.mitre_attack import get_attack_techniques
    from agent_bom.mitre_fetch import get_attack_version

    catalogue = get_attack_techniques()
    findings = list(findings)
    refs = _collect_technique_refs(findings, tag_fields=_ATTACK_TAG_FIELDS, valid_ids=catalogue)
    covered = _covered_techniques(refs, labels=catalogue)
    total = len(catalogue)
    return {
        "framework": "mitre_attack",
        "name": "MITRE ATT&CK Enterprise",
        "evidence_source": "finding.attack_tags",
        "catalogue_total": total,
        "catalogue_version": get_attack_version(),
        "covered_count": len(covered),
        "coverage_pct": _coverage_pct(len(covered), total),
        "covered_techniques": covered,
    }


def build_atlas_coverage(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Coverage of MITRE ATLAS techniques by finding evidence.

    ``catalogue_total`` is the curated tag surface (the techniques findings can
    actually be mapped to); ``catalogue_upstream_total`` discloses the full
    upstream ATLAS catalogue so the number is not read as total ATLAS coverage.
    """
    from agent_bom import atlas

    catalogue = dict(atlas.ATLAS_TECHNIQUES)
    findings = list(findings)
    refs = _collect_technique_refs(findings, tag_fields=_ATLAS_TAG_FIELDS, valid_ids=catalogue)
    covered = _covered_techniques(refs, labels=catalogue, label_fn=atlas.atlas_label)
    total = atlas.curated_total()
    return {
        "framework": "mitre_atlas",
        "name": "MITRE ATLAS",
        "evidence_source": "finding.atlas_tags",
        "catalogue_total": total,
        "catalogue_upstream_total": atlas.upstream_total(),
        "covered_count": len(covered),
        "coverage_pct": _coverage_pct(len(covered), total),
        "covered_techniques": covered,
    }


def build_maestro_coverage(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Coverage of MAESTRO layers by finding evidence.

    A layer is credited only when a finding's ``source`` maps *explicitly* to
    it. The default ``KC6`` fallback used elsewhere is deliberately not applied
    here, so an unmapped source never fabricates infrastructure-layer coverage.
    """
    from agent_bom.maestro import _SOURCE_TO_LAYER, LAYER_DESCRIPTIONS, MaestroLayer, layer_label

    findings = list(findings)
    # Layer id ("KC1") -> ordered, de-duplicated finding refs.
    refs: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for finding in findings:
        if not isinstance(finding, Mapping):
            continue
        source = str(finding.get("source") or "").strip().lower()
        if not source:
            continue
        layer = _SOURCE_TO_LAYER.get(source)
        if layer is None:
            continue
        layer_id = layer.value.split(":", 1)[0].strip()
        ref = _finding_ref(finding)
        bucket = refs.setdefault(layer_id, [])
        seen_refs = seen.setdefault(layer_id, set())
        if ref and ref not in seen_refs:
            seen_refs.add(ref)
            bucket.append(ref)

    covered: list[dict[str, Any]] = []
    for layer_id in sorted(refs):
        ordered = refs[layer_id]
        layer = next((la for la in MaestroLayer if la.value.startswith(f"{layer_id}:")), None)
        label = layer_label(layer) if layer is not None else layer_id
        covered.append(
            {
                "id": layer_id,
                "label": label,
                "finding_count": len(ordered),
                "finding_refs": ordered[:_MAX_REFS_PER_TECHNIQUE],
                "finding_refs_truncated": len(ordered) > _MAX_REFS_PER_TECHNIQUE,
            }
        )

    total = len(LAYER_DESCRIPTIONS)
    return {
        "framework": "mitre_maestro",
        "name": "MAESTRO",
        "evidence_source": "finding.source -> MAESTRO layer",
        "catalogue_total": total,
        "covered_count": len(covered),
        "coverage_pct": _coverage_pct(len(covered), total),
        "covered_techniques": covered,
    }


def build_mitre_coverage(findings: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """Unified coverage across ATT&CK, ATLAS, and MAESTRO.

    ``findings`` is materialized once and shared across all three builders so
    the caller pays a single pass over the tenant's findings.
    """
    materialized = list(findings)
    return {
        "covered_definition": COVERED_DEFINITION,
        "uncovered_definition": UNCOVERED_DEFINITION,
        "finding_count": len(materialized),
        "frameworks": [
            build_attack_coverage(materialized),
            build_atlas_coverage(materialized),
            build_maestro_coverage(materialized),
        ],
    }
