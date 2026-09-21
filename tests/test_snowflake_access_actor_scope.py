"""Missing query roles cannot combine unrelated actors into broad access findings."""

from dataclasses import replace

import pytest

from agent_bom.cloud.snowflake import _find_sensitive_data_access, _find_write_access_risks
from agent_bom.governance import AccessRecord, DataClassification, GovernanceReport, GovernanceSeverity
from agent_bom.models import AIBOMReport


def _record(index, *, role="", user=None, query=None):
    return AccessRecord(
        query_id=f"q{index}" if query is None else query,
        user_name=f"user{index}" if user is None else user,
        role_name=role,
        query_start="2026-09-20T12:00:00Z",
        object_name=f"DB.PUBLIC.T{index}",
        object_type="TABLE",
        operation="WRITE",
        is_write=True,
    )


def test_missing_roles_do_not_collapse_distinct_users_into_broad_writes():
    report = GovernanceReport(account="ACCT")
    report.access_records = [_record(i) for i in range(5)]
    report.findings = _find_write_access_risks(report)
    assert len(report.findings) == 5
    assert all(f.severity == GovernanceSeverity.MEDIUM for f in report.findings)
    assert {f.details["actor_id"] for f in report.findings} == {f"user{i}" for i in range(5)}
    assert all(f.details["actor_type"] == "user" for f in report.findings)
    assert all("query role unavailable" in f.description for f in report.findings)
    assert all(len(f.details["tables"]) == 1 for f in report.findings)
    # Actor typing also survives promotion into the unified findings contract.
    unified = AIBOMReport(agents=[])
    unified.snowflake_governance_data = report.to_dict()
    promoted = unified.to_findings()
    assert len({f.id for f in promoted}) == 5
    assert {f.evidence["details"]["actor_id"] for f in promoted} == {f"user{i}" for i in range(5)}


def test_user_and_role_with_identical_name_stay_separate():
    report = GovernanceReport(account="ACCT")
    report.access_records = [_record(0, role="BOT"), _record(1, user="BOT")]
    findings = _find_write_access_risks(report)
    assert {(f.details["actor_type"], f.details["actor_id"]) for f in findings} == {("role", "BOT"), ("user", "BOT")}
    assert len({f.title for f in findings}) == 2


def test_unattributed_queries_and_records_never_become_one_actor():
    report = GovernanceReport(account="ACCT")
    report.access_records = [_record(0, user=""), _record(1, user=""), _record(2, user="", query=""), _record(3, user="", query="")]
    findings = _find_write_access_risks(report)
    assert len(findings) == 4
    assert [f.details["actor_type"] for f in findings].count("query") == 2
    assert [f.details["actor_type"] for f in findings].count("record") == 2
    assert all(f.agent_or_role == "" for f in findings)
    assert all("identity unavailable" in f.description for f in findings)


@pytest.mark.parametrize(("tag", "table_field"), [("PII", "pii_tables"), ("FINANCIAL", "tables")])
def test_sensitive_access_without_roles_is_scoped_to_each_known_user(tag, table_field):
    report = GovernanceReport(account="ACCT")
    report.access_records = [_record(0), _record(1)]
    report.data_classifications = [DataClassification(object_name=f"DB.PUBLIC.T{i}", object_type="TABLE", tag_name=tag) for i in range(2)]
    findings = _find_sensitive_data_access(report)
    assert len(findings) == 2
    assert all(f.details["actor_type"] == "user" for f in findings)
    assert {tuple(f.details[table_field]) for f in findings} == {("DB.PUBLIC.T0",), ("DB.PUBLIC.T1",)}
    assert all("query role unavailable" in f.description for f in findings)
    assert all("Role ''" not in f.description for f in findings)


def test_known_role_aggregation_remains_explicit_and_deduplicated():
    report = GovernanceReport(account="ACCT")
    report.access_records = [_record(i, role="ETL") for i in range(5)]
    report.access_records.append(replace(report.access_records[0], query_id="repeated-query"))
    findings = _find_write_access_risks(report)
    assert len(findings) == 1
    assert findings[0].severity == GovernanceSeverity.HIGH
    assert len(findings[0].details["tables"]) == 5
    assert "recorded role 'ETL'" in findings[0].description
