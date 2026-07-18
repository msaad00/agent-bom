"""Catalog-backed NIST SP 800-53 Rev 5 scoring — the single source of truth.

The ``/v1/compliance`` route, its ``/compliance/nist-800-53`` drill, the MCP
``compliance`` tool, the auditor compliance narrative, and the CLI all score the
vendored NIST 800-53 catalog through the functions here, so every surface reports
the SAME numbers by construction (§11 one-source-of-truth). No FastAPI / CLI /
MCP dependency lives in this module — it takes plain blast-radius dicts + a CIS
status map and returns plain dicts.

Scoring is over EVALUATED controls only (a control is evaluated when at least one
vendor-asserted evidencing check ran): findings can only fail/warn, a CIS
Foundations check contributes pass/fail/error, ERROR is an explicit bucket
counted toward the evaluated denominator but never the numerator, and a control
with no run check stays ``not_evaluated`` against the full catalog. The line is
scored INDEPENDENTLY and is never folded into ``overall_score`` (the same
CVE/CIS evidence already drives the existing per-framework lines — folding it
would double-count). All framework mappings here are VENDOR-ASSERTED, never an
authority-published crosswalk; ISO/IEC 27001 attribution is surfaced BY ID ONLY
(ISO titles are copyrighted) via NIST's official SP 800-53 → ISO crosswalk.
"""

from __future__ import annotations

from typing import Any

# Order used to collapse multiple evidence signals on one NIST control into a
# single status. Higher wins: a real weakness (fail/warning) beats an
# unevaluable check (error) which beats a clean pass; a control with no run
# check stays not_evaluated (never a silent pass).
NIST_STATUS_RANK = {"not_evaluated": 0, "pass": 1, "error": 2, "warning": 3, "fail": 4}

NIST_800_53_FRAMEWORK_LABEL = "NIST SP 800-53 Rev 5"


def evaluated_control_status(sev_breakdown: dict[str, int]) -> str:
    """Status of a control that HAS mapped findings, by worst severity.

    Mirror of ``compliance_narrative._control_status`` so ``/v1/compliance``, the
    narrative, and the CLI export agree: critical/high → fail, medium/low →
    warning. The caller only reaches this with findings > 0, so an all-zero
    breakdown means the mapped findings are all unrated-severity — evidence
    exists but severity is ungraded, which is ``not_evaluated``, never a silent
    pass (a false pass inflated overall_score). Keep in sync with that function.
    """
    if sev_breakdown.get("critical", 0) > 0 or sev_breakdown.get("high", 0) > 0:
        return "fail"
    if sev_breakdown.get("medium", 0) > 0 or sev_breakdown.get("low", 0) > 0:
        return "warning"
    return "not_evaluated"


def build_nist_800_53_catalog_line(
    all_blast: list[dict],
    cis_statuses: dict[tuple[str, str], str],
    scan_count: int,
) -> dict[str, Any]:
    """Score the full vendored NIST SP 800-53 Rev 5 catalog over EVALUATED
    controls only, using the curated (vendor-asserted) check → control map.

    A control is *evaluated* when at least one mapped check ran: a CVE/CWE
    finding whose ``nist_800_53_tags`` include a curated (evidencing_checks)
    control, or a CIS Foundations check the vendor-asserted table maps to it.
    Findings can only fail/warn (absence of a CVE is never a pass); a CIS check
    contributes pass/fail/error. ERROR is an explicit bucket — counted toward the
    evaluated denominator but never the numerator. Controls with no run check are
    ``not_evaluated`` against the full catalog. Scored INDEPENDENTLY: this line is
    never folded into ``overall_score``.
    """
    from agent_bom import framework_mapping as fm

    catalog = fm.FRAMEWORK_CONTROL_CATALOG.get(fm.FRAMEWORK_NIST_800_53, {})
    evidenced = fm.NIST_800_53_EVIDENCED_CONTROLS

    # Finding-driven severity per curated control (worst-severity → status via
    # the shared evaluated_control_status helper the rest of the scorecard uses).
    finding_sev: dict[str, dict[str, int]] = {}
    finding_count: dict[str, int] = {}
    for br in all_blast:
        for control_id in br.get("nist_800_53_tags", []) or []:
            if control_id not in evidenced:
                continue  # vuln-intrinsic tag with no curated check → reconcile out
            sev = str(br.get("severity") or "").lower()
            bucket = finding_sev.setdefault(control_id, {"critical": 0, "high": 0, "medium": 0, "low": 0})
            if sev in bucket:
                bucket[sev] += 1
            finding_count[control_id] = finding_count.get(control_id, 0) + 1

    # CIS-driven statuses per control via the vendor-asserted CIS → NIST table.
    cis_by_control: dict[str, set[str]] = {}
    for (cloud, check_id), status in cis_statuses.items():
        if status not in ("pass", "fail", "error"):
            continue  # not_applicable / unknown never evaluate a control
        for control_id in fm.nist_controls_for_cis_check(cloud, check_id):
            cis_by_control.setdefault(control_id, set()).add(status)

    controls: list[dict[str, Any]] = []
    tally = {"pass": 0, "fail": 0, "warning": 0, "error": 0}
    for control_id in sorted(evidenced):
        signals: set[str] = set()
        if control_id in finding_sev:
            fstatus = evaluated_control_status(finding_sev[control_id])
            if fstatus != "not_evaluated":  # all-unrated findings are not evidence
                signals.add(fstatus)
        for cis_status in cis_by_control.get(control_id, set()):
            signals.add("warning" if cis_status == "warn" else cis_status)
        if not signals:
            continue  # curated control, but nothing ran → not_evaluated
        status = max(signals, key=lambda s: NIST_STATUS_RANK[s])
        tally[status] += 1
        spec = catalog.get(control_id)
        iso_ids = fm.nist_to_iso(control_id) if status == "fail" else []
        controls.append(
            {
                "control_id": control_id,
                "title": spec.title if spec else None,
                "status": status,
                "findings": finding_count.get(control_id, 0),
                "evidencing_checks": list(spec.evidencing_checks) if spec else [],
                "iso_27001_derived": iso_ids,
            }
        )

    passed, failed, warned, errored = tally["pass"], tally["fail"], tally["warning"], tally["error"]
    evaluated = passed + failed + warned + errored
    catalog_size = len(catalog)
    not_evaluated = catalog_size - evaluated
    score = round((passed / evaluated) * 100, 1) if evaluated > 0 else 0.0
    coverage_pct = round((evaluated / catalog_size) * 100, 2) if catalog_size > 0 else 0.0

    if scan_count == 0 or evaluated == 0:
        status = "no_data"
    elif failed > 0:
        status = "fail"
    elif warned > 0 or errored > 0:
        status = "warning"
    else:
        status = "pass"

    # Emergent cross-framework: failing NIST controls implicate ISO Annex A
    # controls via NIST's own official SP 800-53 → ISO 27001 crosswalk. Surface
    # BY ID ONLY (ISO titles are copyrighted), clearly labeled as derived.
    iso_derived_ids = sorted({iso for c in controls if c["status"] == "fail" for iso in c["iso_27001_derived"]})

    return {
        "framework": "nist-800-53",
        "framework_key": "nist_800_53_catalog",
        "framework_label": NIST_800_53_FRAMEWORK_LABEL,
        "representation": "catalog",
        "source": "framework_control_catalog",
        "vendor_asserted": True,
        "status": status,
        "score": score,
        "summary": {
            "pass": passed,
            "fail": failed,
            "warning": warned,
            "error": errored,
            "evaluated": evaluated,
            "not_evaluated": not_evaluated,
            "catalog_size": catalog_size,
            "coverage_pct": coverage_pct,
            "score": score,
        },
        "controls": controls,
        "iso_27001_derived": {
            "source": "nist_800_53_to_iso_27001_crosswalk",
            "note": (
                "ISO/IEC 27001:2022 Annex A control IDs implicated by the failing NIST controls, "
                "derived from NIST's official SP 800-53 Rev 5 -> ISO 27001 crosswalk (identifiers only)."
            ),
            "controls": iso_derived_ids,
        },
    }


def nist_family(control_id: str) -> str:
    """Return the NIST 800-53 family prefix (AC, AU, SC, …) for a control id."""
    return control_id.split("-", 1)[0]


def build_family_rollup(evaluated_controls: list[dict], catalog: dict[str, Any]) -> list[dict]:
    """Partition the FULL vendored catalog into families and fold the evaluated
    per-control statuses into each. ``total`` counts every catalog control in the
    family; ``evaluated`` / ``pass`` / ``fail`` / … come from the scored controls;
    ``not_evaluated`` is the remainder. Sums reconcile with the catalog line by
    construction, giving the UI a scale-aware grouping over 1000+ controls.
    """
    fam: dict[str, dict[str, int]] = {}
    for control_id in catalog:
        rec = fam.setdefault(
            nist_family(control_id),
            {"total": 0, "evaluated": 0, "pass": 0, "fail": 0, "warning": 0, "error": 0, "not_evaluated": 0},
        )
        rec["total"] += 1
    for control in evaluated_controls:
        rec = fam.get(nist_family(control["control_id"]))
        if rec is None:
            continue
        st = control["status"]
        if st in ("pass", "fail", "warning", "error"):
            rec["evaluated"] += 1
            rec[st] += 1
    out: list[dict] = []
    for name in sorted(fam):
        rec = fam[name]
        rec["not_evaluated"] = rec["total"] - rec["evaluated"]
        out.append({"family": name, **rec})
    return out


def build_nist_800_53_drill(
    line: dict[str, Any],
    *,
    status: str | None = None,
    include_not_evaluated: bool = False,
) -> dict[str, Any]:
    """Expand a catalog line into a per-control drill: family rollup, optional
    full-catalog listing, and a display-only status filter.

    The headline ``summary`` / ``score`` / ``status`` are carried through
    unchanged from ``line`` (one source of truth). By default only EVALUATED
    controls are listed; ``include_not_evaluated`` enumerates the full catalog
    (each unrun control as ``not_evaluated`` — never a silent pass); ``status``
    (comma-separated) filters the displayed list WITHOUT changing the counts.
    """
    from agent_bom import framework_mapping as fm

    catalog = fm.FRAMEWORK_CONTROL_CATALOG.get(fm.FRAMEWORK_NIST_800_53, {})
    evaluated_controls = list(line.get("controls", []))
    families = build_family_rollup(evaluated_controls, catalog)

    controls = list(evaluated_controls)
    if include_not_evaluated:
        evaluated_ids = {c["control_id"] for c in evaluated_controls}
        for control_id in sorted(catalog):
            if control_id in evaluated_ids:
                continue
            spec = catalog[control_id]
            controls.append(
                {
                    "control_id": control_id,
                    "title": spec.title,
                    "status": "not_evaluated",
                    "findings": 0,
                    "evidencing_checks": list(spec.evidencing_checks),
                    "iso_27001_derived": [],
                }
            )

    if status:
        wanted = {s.strip() for s in status.split(",") if s.strip()}
        controls = [c for c in controls if c["status"] in wanted]

    return {
        "framework": line["framework"],
        "framework_key": line["framework_key"],
        "framework_label": line["framework_label"],
        "representation": line["representation"],
        "source": line["source"],
        "vendor_asserted": line["vendor_asserted"],
        "status": line["status"],
        "score": line["score"],
        "summary": line["summary"],
        "families": families,
        "controls": controls,
        "iso_27001_derived": line["iso_27001_derived"],
    }
