"""Tests for the scanner importer registry and the Prowler / Security Hub importers."""

from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV
from agent_bom.finding import FindingSource, FindingType
from agent_bom.findings_push import load_push_findings
from agent_bom.parsers.external_scanners import ingest_external_report, load_external_report
from agent_bom.parsers.importers import (
    ExternalScanImport,
    ImporterManifest,
    _reset_importer_registry_for_tests,
    detect_importer,
    importer_manifests,
    importer_registry_warnings,
    list_importers,
)

FIXTURES = Path(__file__).parent / "fixtures" / "importers"


def _load(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(autouse=True)
def reset_importer_registry(monkeypatch):
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    _reset_importer_registry_for_tests()
    yield
    _reset_importer_registry_for_tests()


# ── Transparency manifest ─────────────────────────────────────────────────


def test_builtin_manifests_are_offline_and_credential_free():
    manifests = {manifest["name"]: manifest for manifest in importer_manifests()}
    assert set(manifests) == {"prowler", "securityhub"}
    for manifest in manifests.values():
        assert manifest["network_access"] is False
        assert manifest["credentials_required"] is None
        assert manifest["data_retained"]
        assert manifest["default_filters"]


# ── Detection ─────────────────────────────────────────────────────────────


def test_detects_prowler_and_securityhub_shapes():
    assert detect_importer(_load("prowler_ocsf.json")).manifest.name == "prowler"
    asff = _load("securityhub_asff.json")
    assert detect_importer(asff).manifest.name == "securityhub"
    assert detect_importer(asff["Findings"]).manifest.name == "securityhub"
    assert detect_importer({"Findings": []}).manifest.name == "securityhub"


@pytest.mark.parametrize(
    "payload",
    [[], [{"title": "x"}], {"Results": []}, {"Findings": [{"title": "x"}]}, [{"finding_info": {}, "status_code": "FAIL"}], "text", 7],
)
def test_detection_rejects_foreign_shapes(payload):
    assert detect_importer(payload) is None


def test_unknown_list_raises_supported_format_hint():
    with pytest.raises(ValueError, match="Prowler JSON-OCSF"):
        ingest_external_report([{"title": "not a scanner export"}])


# ── Prowler mapping ───────────────────────────────────────────────────────


def test_prowler_imports_fail_and_manual_and_skips_pass_and_muted():
    imported = ingest_external_report(_load("prowler_ocsf.json"))

    assert imported.format == "prowler"
    assert imported.packages == []
    by_check = {finding.evidence["check_id"]: finding for finding in imported.findings}
    assert set(by_check) == {"s3_bucket_public_access", "account_security_contact_information_is_registered"}
    assert by_check["account_security_contact_information_is_registered"].finding_type == FindingType.CLOUD_BEST_PRACTICE_ERROR
    assert imported.notices == ["Prowler: skipped 1 PASS result(s), 1 muted result(s) by default import rules."]


def test_prowler_finding_carries_scope_provenance_and_compliance():
    imported = ingest_external_report(_load("prowler_ocsf.json"))
    finding = next(f for f in imported.findings if f.evidence["check_id"] == "s3_bucket_public_access")

    assert finding.finding_type == FindingType.CLOUD_BEST_PRACTICE_FAIL
    assert finding.source == FindingSource.CLOUD_SECURITY
    assert finding.severity == "critical"
    assert finding.asset.asset_type == "cloud_resource"
    assert finding.asset.identifier == "arn:aws:s3:::example-data"
    assert finding.provider == "aws"
    assert finding.account_ref == "aws:123456789012"
    assert finding.region == "us-east-1"
    assert finding.sources == ["external:prowler"]
    assert finding.to_dict()["security_domain"] == "cspm"
    assert finding.evidence["external_tool_version"] == "5.4.0"
    assert finding.evidence["compliance"] == {"CIS-3.0": ["2.1.4"], "SOC2": ["cc_6_1"]}
    assert {(tag.framework, tag.control) for tag in finding.controls} >= {("prowler:cis_3_0", "2.1.4"), ("prowler:soc2", "cc_6_1")}
    assert "Block Public Access" in (finding.remediation_guidance or "")


def test_prowler_ids_are_stable_and_duplicates_collapse():
    rows = _load("prowler_ocsf.json")
    first = ingest_external_report(rows)
    second = ingest_external_report(copy.deepcopy(rows) + [copy.deepcopy(rows[0])])
    assert [f.id for f in first.findings] == [f.id for f in second.findings]


def test_prowler_rejects_oversized_reports(monkeypatch):
    monkeypatch.setattr("agent_bom.parsers.importers._common.MAX_IMPORT_RECORDS", 2)
    with pytest.raises(ValueError, match="split it"):
        ingest_external_report(_load("prowler_ocsf.json"))


def test_prowler_tolerates_malformed_fields():
    row = _load("prowler_ocsf.json")[0]
    row.update(resources="not-a-list", cloud=["bad"], unmapped={"compliance": "bad"}, severity=None, severity_id=4)
    row["remediation"] = {"references": "bad"}
    imported = ingest_external_report([row])
    finding = imported.findings[0]
    assert finding.severity == "high"
    assert finding.asset.identifier == "cloud-account"
    assert finding.provider is None


# ── Security Hub mapping ──────────────────────────────────────────────────


def test_securityhub_skip_rules_and_tool_attribution():
    imported = ingest_external_report(_load("securityhub_asff.json"))

    assert imported.format == "securityhub"
    assert imported.tool_names == ["Security Hub", "Inspector"]
    assert len(imported.findings) == 2
    assert imported.notices == ["Security Hub: skipped 2 suppressed or resolved finding(s), 1 archived finding(s) by default import rules."]


def test_securityhub_control_finding_mapping():
    imported = ingest_external_report(_load("securityhub_asff.json"))
    finding = next(f for f in imported.findings if f.finding_type == FindingType.CLOUD_BEST_PRACTICE_FAIL)

    assert finding.severity == "high"
    assert finding.asset.identifier == "arn:aws:s3:::example-data"
    assert finding.account_ref == "aws:123456789012"
    assert finding.evidence["control_id"] == "S3.8"
    assert finding.evidence["product_name"] == "Security Hub"
    assert finding.evidence["compliance"] == {"NIST.800-53.r5": ["AC-21"], "CIS AWS Foundations Benchmark": ["v3.0.0/2.1.4"]}
    assert finding.sources == ["external:aws-securityhub"]
    assert "remediation" in (finding.remediation_guidance or "")


def test_securityhub_vulnerabilities_become_cve_findings():
    imported = ingest_external_report(_load("securityhub_asff.json"))
    finding = next(f for f in imported.findings if f.finding_type == FindingType.CVE)

    assert finding.cve_id == "CVE-2023-38545"
    assert finding.source == FindingSource.EXTERNAL
    assert finding.severity == "critical"
    assert finding.cvss_score == 9.8
    assert finding.fixed_version == "8.4.0"
    assert finding.evidence["package_name"] == "curl"
    assert finding.asset.identifier.startswith("arn:aws:ecr:us-east-1:123456789012:repository/app")


def test_securityhub_bare_list_matches_wrapped_response_ids():
    payload = _load("securityhub_asff.json")
    wrapped = ingest_external_report(payload)
    bare = ingest_external_report(payload["Findings"])
    assert [f.id for f in wrapped.findings] == [f.id for f in bare.findings]


def test_securityhub_normalized_severity_fallback_and_bad_cvss():
    row = copy.deepcopy(_load("securityhub_asff.json")["Findings"][1])
    row["Severity"] = {"Normalized": 45}
    row["Vulnerabilities"][0]["Cvss"] = [{"BaseScore": "99"}]
    finding = ingest_external_report({"Findings": [row]}).findings[0]
    assert finding.severity == "medium"
    assert finding.cvss_score is None


def test_securityhub_empty_response_is_a_clean_import():
    imported = ingest_external_report({"Findings": []})
    assert imported.findings == [] and imported.notices == []


def test_securityhub_counts_non_asff_records_and_rejects_non_list():
    row = _load("securityhub_asff.json")["Findings"][0]
    imported = ingest_external_report({"Findings": [row, "bad", {"Id": "no-schema"}]})
    assert len(imported.findings) == 1
    assert imported.notices == ["Security Hub: skipped 1 record(s) that are not ASFF findings by default import rules."]
    with pytest.raises(ValueError, match="Unrecognized"):
        ingest_external_report({"Findings": "bad"})


# ── File path + size limit ────────────────────────────────────────────────


def test_load_external_report_enforces_parser_size_limit(tmp_path, monkeypatch):
    report = tmp_path / "prowler.ocsf.json"
    report.write_text(json.dumps(_load("prowler_ocsf.json")), encoding="utf-8")
    assert load_external_report(report).format == "prowler"
    monkeypatch.setenv("AGENT_BOM_MAX_MANIFEST_BYTES", "16")
    with pytest.raises(ValueError, match="size limit"):
        load_external_report(report)


def test_findings_push_routes_scanner_lists_through_importers():
    rows = load_push_findings(_load("prowler_ocsf.json"), source="prowler")
    assert len(rows) == 2
    assert {row["source"] for row in rows} == {"prowler"}
    plain = [{"title": "pre-normalized row", "severity": "high"}]
    assert load_push_findings(plain) == plain


# ── Third-party importers via entry points ────────────────────────────────


class _AcmeImporter:
    manifest = ImporterManifest(
        name="acme",
        display_name="Acme scanner",
        tool="acme",
        formats=("acme-json",),
        detection='object with "acme_version"',
        data_retained="none",
    )

    def sniff(self, data: object) -> bool:
        return isinstance(data, dict) and "acme_version" in data

    def parse(self, data: object) -> ExternalScanImport:
        return ExternalScanImport(format="acme", tool_names=["acme"])


class _ShadowImporter(_AcmeImporter):
    manifest = ImporterManifest("prowler", "Shadow", "shadow", (), "never", "none")


class FakeEntryPoint:
    def __init__(self, name: str, loader: Callable[[], Any]) -> None:
        self.name = name
        self.group = "agent_bom.importers"
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class FakeEntryPoints(list):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry_point for entry_point in self if entry_point.group == group]


def _patch_entry_points(monkeypatch, entries: list[FakeEntryPoint]) -> None:
    monkeypatch.setattr("agent_bom.extensions.metadata.entry_points", lambda: FakeEntryPoints(entries))


def test_entry_point_importers_require_opt_in(monkeypatch):
    _patch_entry_points(monkeypatch, [FakeEntryPoint("acme", lambda: _AcmeImporter)])
    assert [importer.manifest.name for importer in list_importers()] == ["prowler", "securityhub"]
    with pytest.raises(ValueError, match="Unrecognized"):
        ingest_external_report({"acme_version": 1})


def test_entry_point_importer_registers_after_builtins(monkeypatch):
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint("acme", lambda: _AcmeImporter),
            FakeEntryPoint("shadow", lambda: _ShadowImporter),
            FakeEntryPoint("broken", lambda: object()),
        ],
    )

    assert [importer.manifest.name for importer in list_importers()] == ["prowler", "securityhub", "acme"]
    assert ingest_external_report({"acme_version": 1}).format == "acme"
    warnings = " ".join(importer_registry_warnings())
    assert "already registered" in warnings
    assert "broken" in warnings
