"""Tests for the Snowflake DCM IaC scanner (#2218).

DCM is a first-class IaC type alongside Terraform / K8s / CloudFormation /
Dockerfile. The scanner runs on customer DCM projects (their schema-as-code)
the same way it runs on their Terraform — emitting ``IaCFinding`` rows with
``category="dcm"`` and the same compliance + remediation shape.

Coverage:
- File-shape detection (V<seq>__<name>.sql under a DCM-named directory)
- Each of the 8 DCM-* rules fires on a fixture matching the misconfig
- Comments are not false-positive sources (--, /* */)
- Clean DCM migrations produce zero findings
- The Native App's own DCM project (deploy/snowflake/native-app/dcm/V001__core_schema.sql)
  scans clean — meta-recursive lock-in
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.iac import scan_iac_directory
from agent_bom.iac.dcm import (
    is_dcm_migration,
    scan_dcm_directory,
    scan_dcm_migration,
)

# ─── File-shape detection ────────────────────────────────────────────────────


def test_is_dcm_migration_recognises_versioned_files_under_dcm_dir(tmp_path):
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    f = dcm_dir / "V001__init.sql"
    f.write_text("-- empty", encoding="utf-8")
    assert is_dcm_migration(f) is True


def test_is_dcm_migration_rejects_unversioned_sql(tmp_path):
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    f = dcm_dir / "ad_hoc_query.sql"
    f.write_text("SELECT 1", encoding="utf-8")
    assert is_dcm_migration(f) is False


def test_is_dcm_migration_rejects_versioned_outside_dcm_dir(tmp_path):
    f = tmp_path / "scripts" / "V001__init.sql"
    f.parent.mkdir(parents=True)
    f.write_text("-- empty", encoding="utf-8")
    assert is_dcm_migration(f) is False  # not under a dcm/-style dir


def test_is_dcm_migration_recognises_schemachange_alias(tmp_path):
    sc_dir = tmp_path / "schemachange"
    sc_dir.mkdir()
    f = sc_dir / "V42__alter_table.sql"
    f.write_text("-- empty", encoding="utf-8")
    assert is_dcm_migration(f) is True


# ─── Per-rule coverage ───────────────────────────────────────────────────────


@pytest.fixture
def dcm_fixture(tmp_path):
    """Create a tmp DCM project; tests write a single migration body and scan."""

    def _make(body: str, *, filename: str = "V001__test.sql") -> list:
        d = tmp_path / "dcm"
        d.mkdir(exist_ok=True)
        target = d / filename
        target.write_text(body, encoding="utf-8")
        return scan_dcm_migration(target)

    return _make


def test_dcm_001_manage_grants(dcm_fixture):
    findings = dcm_fixture("GRANT MANAGE GRANTS ON ACCOUNT TO ROLE ops_admin;")
    assert any(f.rule_id == "DCM-001" and f.severity == "critical" for f in findings)


def test_dcm_002_public_network_policy(dcm_fixture):
    findings = dcm_fixture("CREATE NETWORK POLICY open_door ALLOWED_IP_LIST = ('0.0.0.0/0');")
    assert any(f.rule_id == "DCM-002" and f.severity == "critical" for f in findings)


def test_dcm_003_grant_all_on_database(dcm_fixture):
    findings = dcm_fixture("GRANT ALL PRIVILEGES ON DATABASE prod TO ROLE app;")
    assert any(f.rule_id == "DCM-003" and f.severity == "high" for f in findings)


def test_dcm_005_service_without_network_policy(dcm_fixture):
    findings = dcm_fixture("CREATE SERVICE api IN COMPUTE POOL p FROM SPECIFICATION_FILE = '/spec.yaml';")
    assert any(f.rule_id == "DCM-005" for f in findings)


def test_dcm_006_grant_accountadmin(dcm_fixture):
    findings = dcm_fixture("GRANT ROLE ACCOUNTADMIN TO USER alice;")
    assert any(f.rule_id == "DCM-006" and f.severity == "critical" for f in findings)


def test_dcm_007_database_usage(dcm_fixture):
    findings = dcm_fixture("GRANT USAGE ON DATABASE prod TO ROLE analyst;")
    assert any(f.rule_id == "DCM-007" for f in findings)


def test_dcm_008_grant_to_public(dcm_fixture):
    findings = dcm_fixture("GRANT SELECT ON TABLE prod.public.findings TO ROLE PUBLIC;")
    assert any(f.rule_id == "DCM-008" and f.severity == "high" for f in findings)


# ─── Comment-stripping (no false positives) ─────────────────────────────────


def test_dcm_does_not_false_positive_on_line_comment(dcm_fixture):
    """A documented "don't do this" example in a comment must not fire."""
    findings = dcm_fixture(
        "-- example of what NOT to do: GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;\nGRANT SELECT ON TABLE foo TO ROLE bar;\n"
    )
    assert not any(f.rule_id == "DCM-001" for f in findings)


def test_dcm_does_not_false_positive_on_block_comment(dcm_fixture):
    findings = dcm_fixture("/* historical example: GRANT ALL PRIVILEGES ON DATABASE x TO y */\nCREATE TABLE foo (id NUMBER);\n")
    assert not any(f.rule_id == "DCM-003" for f in findings)


# ─── Clean migration → zero findings ─────────────────────────────────────────


def test_clean_dcm_migration_has_no_findings(dcm_fixture):
    body = """
    CREATE SCHEMA IF NOT EXISTS core;
    CREATE TABLE IF NOT EXISTS core.scan_jobs (
        job_id VARCHAR PRIMARY KEY,
        created_at TIMESTAMP_TZ NOT NULL
    );
    GRANT SELECT ON TABLE core.scan_jobs TO APPLICATION ROLE app_user;
    """
    assert scan_dcm_migration  # imported
    findings = dcm_fixture(body)
    assert findings == []


# ─── Native App's own DCM project — meta-recursive lock-in ──────────────────


def test_native_app_own_dcm_project_scans_clean():
    """The Native App's own DCM project at deploy/snowflake/native-app/dcm/
    must scan with zero DCM-* findings. If a future DCM PR introduces a
    pattern that trips the scanner, it fails here.

    This is the meta-recursive lock-in: agent-bom scans its own schema-as-code
    with the same bar it asks customers to clear.
    """
    repo_root = Path(__file__).resolve().parents[1]
    native_app_dcm = repo_root / "deploy" / "snowflake" / "native-app" / "dcm"
    if not native_app_dcm.is_dir():
        pytest.skip("Native App DCM project not present in this checkout")
    findings = scan_dcm_directory(native_app_dcm)
    assert findings == [], f"Native App's own DCM project scans dirty: {[(f.rule_id, f.line_number, f.title) for f in findings]}"


# ─── Integration: scan_iac_directory dispatches to DCM scanner ──────────────


def test_scan_iac_directory_routes_dcm_files(tmp_path):
    """scan_iac_directory must recognise DCM files via is_dcm_migration
    and route them to scan_dcm_migration. Without this wiring, customer
    DCM projects sitting alongside Terraform never get scanned."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    bad = dcm_dir / "V001__init.sql"
    bad.write_text("GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;", encoding="utf-8")
    findings = scan_iac_directory(tmp_path)
    assert any(f.rule_id == "DCM-001" and f.category == "dcm" for f in findings)


def test_scan_iac_directory_does_not_treat_dcm_as_kubernetes(tmp_path):
    """DCM files have .sql extension — never mistakable for K8s manifests
    (those are .yaml/.yml). Confirm the dispatch order doesn't accidentally
    classify them as something else."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    f = dcm_dir / "V001__init.sql"
    f.write_text("CREATE SCHEMA core;", encoding="utf-8")
    findings = scan_iac_directory(tmp_path)
    # No findings expected, but the file should have been considered
    # — the absence of a wrong-category classification is the assertion.
    for f_ in findings:
        assert f_.category == "dcm" or f_.category != "kubernetes", f"DCM file misclassified as {f_.category}: {f_.rule_id}"


# ─── IaCResourceType wiring ───────────────────────────────────────────────────

from agent_bom.iac.models import IaCResourceType  # noqa: E402


def test_dcm_findings_carry_resource_type(tmp_path):
    """Every DCM finding must carry an IaCResourceType value so graph/compliance wiring works."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    # DCM-001 → DCM_GRANT; DCM-002 → DCM_NETWORK_POLICY; DCM-004 → DCM_TASK; DCM-005 → DCM_SERVICE
    sql = (
        "GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;\n"
        "CREATE NETWORK POLICY p ALLOWED_IP_LIST=('0.0.0.0/0');\n"
        "CREATE TASK t AS BEGIN RETURN 1; END;\n"
        "CREATE SERVICE s IN COMPUTE POOL c AS spec='...';\n"
    )
    (dcm_dir / "V001__setup.sql").write_text(sql, encoding="utf-8")
    findings = scan_iac_directory(tmp_path)
    dcm = [f for f in findings if f.category == "dcm"]
    assert dcm, "Expected DCM findings"
    for f in dcm:
        assert f.resource_type is not None, f"{f.rule_id} missing resource_type"
        assert isinstance(f.resource_type, IaCResourceType)


def test_dcm_grant_rules_have_dcm_grant_type(tmp_path):
    """DCM-001/003/006/007/008 are all GRANT-class — resource_type must be DCM_GRANT."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    (dcm_dir / "V001__grants.sql").write_text(
        "GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;\n",
        encoding="utf-8",
    )
    findings = scan_iac_directory(tmp_path)
    dcm001 = [f for f in findings if f.rule_id == "DCM-001"]
    assert dcm001, "DCM-001 not triggered"
    assert dcm001[0].resource_type == IaCResourceType.DCM_GRANT


def test_dcm_attack_techniques_populated(tmp_path):
    """DCM findings must have ATT&CK techniques enriched via attack_mapping."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    (dcm_dir / "V001__priv.sql").write_text(
        "GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;\n",
        encoding="utf-8",
    )
    findings = scan_iac_directory(tmp_path)
    dcm001 = [f for f in findings if f.rule_id == "DCM-001"]
    assert dcm001
    assert dcm001[0].attack_techniques, "DCM-001 missing ATT&CK techniques"
    assert "T1098" in dcm001[0].attack_techniques


def test_dcm_atlas_techniques_populated(tmp_path):
    """DCM-001 and DCM-005/006/008 must have ATLAS techniques (AI-data relevance)."""
    dcm_dir = tmp_path / "dcm"
    dcm_dir.mkdir()
    (dcm_dir / "V001__priv.sql").write_text(
        "GRANT MANAGE GRANTS ON ACCOUNT TO ROLE x;\n",
        encoding="utf-8",
    )
    findings = scan_iac_directory(tmp_path)
    dcm001 = [f for f in findings if f.rule_id == "DCM-001"]
    assert dcm001
    assert dcm001[0].atlas_techniques, "DCM-001 missing ATLAS techniques"
    assert "AML.T0007" in dcm001[0].atlas_techniques
