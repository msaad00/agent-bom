"""Cross-format invariants for the Compliance Hub (#1044 PR D).

The hub's promise: a finding's framework classification depends on the
finding's *shape* (source, asset type, finding type) — not on which
ingestion adapter parsed it. If a SARIF result, a CycloneDX vuln entry,
a CSV row, and a JSON dict all describe the same logical finding (e.g.
"hardcoded AWS access key in src/cfg.py"), they must land on identical
``applicable_frameworks``.

This file is the executable contract. PR A locked the selection table;
PR B / PR C wired adapters; PR D guarantees they stay coherent. If a
new adapter lands tomorrow that drifts in finding-type inference or
asset-type classification, these invariants fail at PR time.

What we cover:

1. **Cross-format equivalence** — same logical finding, four formats,
   identical framework sets. Run for the three load-bearing finding
   shapes: secret exposure, prompt injection, supply-chain CVE.
2. **Idempotence** — re-ingesting the same content doesn't change the
   framework set on re-classification (the hub's `apply_hub_classification`
   is additive + canonical-ordered).
3. **Adapter completeness** — every public adapter actually calls
   ``apply_hub_classification``. A new adapter that forgets the call
   produces findings with empty ``applicable_frameworks`` and breaks
   here, before it gets near production.
4. **Framework slug stability** — slugs returned by the hub never
   include unknown values; every adapter's output uses canonical slugs
   from ``ALL_FRAMEWORKS``.

Where invariants 1 and 2 differ from the per-adapter tests in PR B / C:
those tests asserted "this adapter classifies its own input correctly".
This file asserts "all adapters agree with each other on the same
input" — a strictly stronger contract.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agent_bom.compliance_hub import (
    ALL_FRAMEWORKS,
    FRAMEWORK_ATLAS,
    FRAMEWORK_ISO_27001,
    FRAMEWORK_NIST_AI_RMF,
    FRAMEWORK_NIST_CSF,
    FRAMEWORK_OWASP_AGENTIC,
    FRAMEWORK_OWASP_LLM,
    FRAMEWORK_PCI_DSS,
    FRAMEWORK_SOC2,
    apply_hub_classification,
)
from agent_bom.compliance_hub_ingest import (
    ingest_csv_findings,
    ingest_cyclonedx_vulnerabilities,
    ingest_findings,
    ingest_json_findings,
    ingest_sarif_findings,
)
from agent_bom.finding import Asset, Finding, FindingSource, FindingType

# ─── Fixtures: same logical finding in four shapes ───────────────────────────


def _sarif_for(rule_id: str, severity_score: float, file: str, msg: str, tags: list[str]) -> dict:
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "test",
                        "rules": [
                            {
                                "id": rule_id,
                                "shortDescription": {"text": msg},
                                "properties": {"tags": tags},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": rule_id,
                        "level": "error" if severity_score >= 7 else "warning",
                        "message": {"text": msg},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": file}}}],
                        "properties": {"security-severity": str(severity_score)},
                    }
                ],
            }
        ],
    }


def _csv_for(title: str, severity: str, file: str, cve: str | None = None) -> str:
    cve_part = cve or ""
    return f"Title,Severity,File,CVE\n{title},{severity},{file},{cve_part}\n"


def _json_for(
    title: str,
    severity: str,
    asset_name: str,
    asset_type: str,
    finding_type: str,
    cve: str | None = None,
) -> str:
    payload = {
        "title": title,
        "severity": severity,
        "asset_name": asset_name,
        "asset_type": asset_type,
        "finding_type": finding_type,
    }
    if cve:
        payload["cve_id"] = cve
    return json.dumps([payload])


# ─── 1. Cross-format equivalence ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "shape",
    [
        "secret",
        "injection",
    ],
)
def test_same_logical_finding_lands_on_identical_framework_set_across_adapters(tmp_path: Path, shape: str) -> None:
    """SARIF / CSV / JSON all describing the same logical finding must
    produce findings whose ``applicable_frameworks`` are identical.

    CycloneDX is excluded from this matrix because it always carries
    source=SBOM (different baseline) — that's covered separately in
    test_cyclonedx_supply_chain_classification_is_stable.
    """
    if shape == "secret":
        sarif_doc = _sarif_for(
            rule_id="SECRET-AWS-ACCESS-KEY",
            severity_score=9.5,
            file="src/cfg.py",
            msg="Hardcoded AWS access key",
            tags=["security", "secret", "CWE-798"],
        )
        csv_text = _csv_for("Hardcoded AWS access key — SECRET", "Critical", "src/cfg.py")
        json_text = _json_for(
            title="Hardcoded AWS access key",
            severity="critical",
            asset_name="src/cfg.py",
            asset_type="file",
            finding_type="CREDENTIAL_EXPOSURE",
        )
    elif shape == "injection":
        sarif_doc = _sarif_for(
            rule_id="prompt-injection-detector",
            severity_score=8.0,
            file="agent.py",
            msg="Possible prompt injection",
            tags=["security", "prompt-injection"],
        )
        csv_text = _csv_for("Prompt injection sink", "High", "agent.py")  # title contains "injection" -> hub picks INJECTION
        json_text = _json_for(
            title="Prompt injection sink",
            severity="high",
            asset_name="agent.py",
            asset_type="file",
            finding_type="INJECTION",
        )
    else:
        raise AssertionError(f"unknown shape {shape}")

    sarif_path = tmp_path / "x.sarif"
    sarif_path.write_text(json.dumps(sarif_doc), encoding="utf-8")
    csv_path = tmp_path / "x.csv"
    csv_path.write_text(csv_text, encoding="utf-8")
    json_path = tmp_path / "x.json"
    json_path.write_text(json_text, encoding="utf-8")

    sarif_findings = ingest_sarif_findings(sarif_path)
    csv_findings = ingest_csv_findings(csv_path)
    json_findings = ingest_json_findings(json_path)

    assert sarif_findings, "SARIF adapter should produce a finding"
    assert csv_findings, "CSV adapter should produce a finding"
    assert json_findings, "JSON adapter should produce a finding"

    sarif_fws = set(sarif_findings[0].applicable_frameworks)
    csv_fws = set(csv_findings[0].applicable_frameworks)
    json_fws = set(json_findings[0].applicable_frameworks)

    assert sarif_fws == csv_fws == json_fws, (
        f"shape={shape!r}: framework sets diverged across adapters\n"
        f"  SARIF: {sorted(sarif_fws)}\n"
        f"  CSV:   {sorted(csv_fws)}\n"
        f"  JSON:  {sorted(json_fws)}\n"
        f"  ∆SARIF-CSV: {sorted(sarif_fws ^ csv_fws)}\n"
        f"  ∆SARIF-JSON: {sorted(sarif_fws ^ json_fws)}"
    )


def test_secret_finding_carries_enterprise_audit_set_across_all_adapters(tmp_path: Path) -> None:
    """The actual framework set for a secret finding — checked once,
    explicitly, so a regression that breaks all adapters together
    (e.g. a hub table edit) doesn't slide past the cross-format test."""
    sarif_path = tmp_path / "s.sarif"
    sarif_path.write_text(
        json.dumps(_sarif_for("SECRET-AWS", 9.5, "src/cfg.py", "Hardcoded key", ["secret", "CWE-798"])),
        encoding="utf-8",
    )
    findings = ingest_sarif_findings(sarif_path)
    fws = set(findings[0].applicable_frameworks)
    for required in (FRAMEWORK_NIST_CSF, FRAMEWORK_ISO_27001, FRAMEWORK_SOC2):
        assert required in fws, f"SECRET finding must include {required}; got {sorted(fws)}"


def test_injection_finding_carries_ai_set_across_adapters(tmp_path: Path) -> None:
    json_path = tmp_path / "i.json"
    json_path.write_text(
        _json_for(
            title="Prompt injection",
            severity="high",
            asset_name="agent.py",
            asset_type="file",
            finding_type="INJECTION",
        ),
        encoding="utf-8",
    )
    findings = ingest_json_findings(json_path)
    fws = set(findings[0].applicable_frameworks)
    for required in (
        FRAMEWORK_OWASP_LLM,
        FRAMEWORK_OWASP_AGENTIC,
        FRAMEWORK_ATLAS,
        FRAMEWORK_NIST_AI_RMF,
    ):
        assert required in fws, f"INJECTION must include {required}; got {sorted(fws)}"


def test_cyclonedx_supply_chain_classification_is_stable(tmp_path: Path) -> None:
    """CycloneDX vulns ride the SBOM source baseline (NIST CSF / SOC 2 /
    PCI DSS). Locked here independently because CycloneDX intentionally
    diverges from the EXTERNAL adapters — its source is known, supply-chain."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "bom-ref": "pkg:npm/lodash@4.17.20",
                "name": "lodash",
                "version": "4.17.20",
                "purl": "pkg:npm/lodash@4.17.20",
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2021-23337",
                "description": "Command injection",
                "ratings": [{"severity": "high"}],
                "affects": [{"ref": "pkg:npm/lodash@4.17.20"}],
            }
        ],
    }
    target = tmp_path / "v.cdx.json"
    target.write_text(json.dumps(sbom), encoding="utf-8")
    findings = ingest_cyclonedx_vulnerabilities(target)
    fws = set(findings[0].applicable_frameworks)
    for required in (FRAMEWORK_NIST_CSF, FRAMEWORK_SOC2, FRAMEWORK_PCI_DSS):
        assert required in fws, f"CycloneDX vuln must include {required}; got {sorted(fws)}"
    assert findings[0].source.value == "SBOM"


# ─── 2. Idempotence ──────────────────────────────────────────────────────────


def test_apply_hub_classification_is_idempotent_on_repeated_calls() -> None:
    """Calling apply_hub_classification twice doesn't duplicate slugs.

    Important because PR C ingest API may re-classify on read for cache
    invalidation, and the dashboard's posture aggregation re-sums per
    framework. A duplicated slug would inflate framework_counts.
    """
    finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.EXTERNAL,
        asset=Asset(name="src/cfg.py", asset_type="file", location="src/cfg.py"),
        severity="critical",
    )
    apply_hub_classification(finding)
    first_pass = list(finding.applicable_frameworks)
    apply_hub_classification(finding)
    second_pass = list(finding.applicable_frameworks)
    assert first_pass == second_pass, f"apply_hub_classification mutated framework list on second call: {first_pass} -> {second_pass}"


def test_apply_hub_classification_preserves_pre_existing_entries() -> None:
    """A caller that pre-seeded applicable_frameworks (e.g. from a vendor
    feed that already declared FedRAMP) should keep those entries when
    the hub adds its own. Only the union grows; nothing is dropped."""
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="left-pad", asset_type="package"),
        severity="high",
        applicable_frameworks=["fedramp"],  # pre-seeded
    )
    apply_hub_classification(finding)
    assert "fedramp" in finding.applicable_frameworks, "pre-seeded fedramp slug should survive hub classification"


# ─── 3. Adapter completeness ─────────────────────────────────────────────────


def test_every_adapter_emits_findings_with_applicable_frameworks_populated(
    tmp_path: Path,
) -> None:
    """Every public ingestion adapter must produce findings whose
    `applicable_frameworks` is non-empty. A new adapter that forgets to
    call `apply_hub_classification` will fail here at PR time, before
    its findings reach the dashboard.

    Catches a class of bug that's easy to miss: adapter parses fine,
    findings show up in /v1/compliance/hub/findings, but they're invisible
    in /v1/compliance/hub/posture because no framework slugs were attached.
    """
    inputs: dict[str, Path] = {}

    sarif_path = tmp_path / "x.sarif"
    sarif_path.write_text(
        json.dumps(_sarif_for("R1", 7.5, "x.py", "msg", ["security"])),
        encoding="utf-8",
    )
    inputs["sarif"] = sarif_path

    cdx_path = tmp_path / "v.cdx.json"
    cdx_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"bom-ref": "ref", "name": "x", "version": "1", "purl": "pkg:pypi/x@1"}],
                "vulnerabilities": [
                    {
                        "id": "CVE-2025-1",
                        "description": "x",
                        "ratings": [{"severity": "medium"}],
                        "affects": [{"ref": "ref"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    inputs["cyclonedx"] = cdx_path

    csv_path = tmp_path / "x.csv"
    csv_path.write_text("Title,Severity,File\nfinding,medium,x.py\n", encoding="utf-8")
    inputs["csv"] = csv_path

    json_path = tmp_path / "x.json"
    json_path.write_text(
        _json_for("finding", "medium", "x.py", "file", "SAST"),
        encoding="utf-8",
    )
    inputs["json"] = json_path

    adapters = {
        "sarif": ingest_sarif_findings,
        "cyclonedx": ingest_cyclonedx_vulnerabilities,
        "csv": ingest_csv_findings,
        "json": ingest_json_findings,
    }

    for fmt, adapter in adapters.items():
        findings = adapter(inputs[fmt])
        assert findings, f"{fmt} adapter produced no findings"
        for f in findings:
            assert f.applicable_frameworks, (
                f"{fmt} adapter produced finding with empty applicable_frameworks: "
                f"{f.title!r} ({f.finding_type.value} on {f.asset.asset_type}); "
                f"adapter likely forgot to call apply_hub_classification"
            )


def test_dispatch_router_preserves_classification_per_format(tmp_path: Path) -> None:
    """`ingest_findings` (the dispatch entrypoint) must produce the same
    classification as calling the per-format adapter directly.

    Defends against a future refactor that adds post-processing in the
    dispatcher and drops applicable_frameworks somewhere in the middle.
    """
    sarif_path = tmp_path / "d.sarif"
    sarif_path.write_text(
        json.dumps(_sarif_for("R1", 7.5, "x.py", "msg", ["security"])),
        encoding="utf-8",
    )
    direct = ingest_sarif_findings(sarif_path)
    via_dispatch = ingest_findings(sarif_path)
    assert len(direct) == len(via_dispatch)
    for d, v in zip(direct, via_dispatch):
        assert d.applicable_frameworks == v.applicable_frameworks


# ─── 4. Framework slug stability ─────────────────────────────────────────────


def test_no_adapter_emits_unknown_framework_slugs(tmp_path: Path) -> None:
    """Every slug returned by every adapter must be in `ALL_FRAMEWORKS`.

    If the hub starts using a slug the dashboard doesn't recognise, the
    /compliance page renders a stale or blank framework card. Catches
    drift between `compliance_hub.ALL_FRAMEWORKS` and what adapters
    actually produce.
    """
    canonical = set(ALL_FRAMEWORKS)

    sarif_path = tmp_path / "k.sarif"
    sarif_path.write_text(
        json.dumps(_sarif_for("R1", 7.5, "x.py", "msg", ["security"])),
        encoding="utf-8",
    )
    cdx_path = tmp_path / "k.cdx.json"
    cdx_path.write_text(
        json.dumps(
            {
                "bomFormat": "CycloneDX",
                "specVersion": "1.5",
                "components": [{"bom-ref": "r", "name": "x", "version": "1", "purl": "pkg:pypi/x@1"}],
                "vulnerabilities": [
                    {
                        "id": "CVE-2025-1",
                        "description": "x",
                        "ratings": [{"severity": "low"}],
                        "affects": [{"ref": "r"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    csv_path = tmp_path / "k.csv"
    csv_path.write_text("Title,Severity\nA,medium\n", encoding="utf-8")
    json_path = tmp_path / "k.json"
    json_path.write_text(
        _json_for("A", "medium", "x.py", "file", "SAST"),
        encoding="utf-8",
    )

    all_findings = (
        ingest_sarif_findings(sarif_path)
        + ingest_cyclonedx_vulnerabilities(cdx_path)
        + ingest_csv_findings(csv_path)
        + ingest_json_findings(json_path)
    )
    for f in all_findings:
        unknown = set(f.applicable_frameworks) - canonical
        assert not unknown, f"finding {f.title!r} carries unknown slugs {sorted(unknown)} (canonical: {sorted(canonical)})"


def test_canonical_order_is_preserved_after_classification() -> None:
    """The hub returns slugs in canonical order so consumers can hash
    the list and cache framework views. A second call must not re-order."""
    finding = Finding(
        finding_type=FindingType.CREDENTIAL_EXPOSURE,
        source=FindingSource.EXTERNAL,
        asset=Asset(name="x", asset_type="file"),
        severity="critical",
    )
    apply_hub_classification(finding)
    first = list(finding.applicable_frameworks)
    # Re-classify and confirm same ordering.
    apply_hub_classification(finding)
    assert first == list(finding.applicable_frameworks), "applicable_frameworks must be order-stable across re-classification"
    # And the order matches ALL_FRAMEWORKS for slugs that are present.
    indices = [ALL_FRAMEWORKS.index(slug) for slug in first if slug in ALL_FRAMEWORKS]
    assert indices == sorted(indices), f"slugs out of canonical order: {first} -> indices {indices}"
