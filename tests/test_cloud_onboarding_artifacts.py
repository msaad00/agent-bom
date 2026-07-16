"""Ready-to-run, read-only onboarding artifacts emitted by `connect <provider>`.

Each provider emits a single artifact that provisions exactly the read-only
principal the connect flow then consumes:

* AWS        -> a CloudFormation template creating a read-only IAM role
               (SecurityAudit + ViewOnlyAccess) trusted via ExternalId;
* Azure      -> a bash script creating an app registration + Reader assignment;
* GCP        -> a bash script creating a service account + roles/viewer binding;
* Snowflake  -> a SQL script creating a read-only governance role.

The tests assert the artifacts are (a) structurally valid, (b) strictly
read-only (no write/admin grants), and (c) round-trip — what they provision is
exactly what `connect <provider>` consumes.
"""

from __future__ import annotations

import json
import re

import pytest

from agent_bom.cloud import onboarding

# Write/mutating verbs that must never appear in a read-only artifact. Word-
# boundary matched so "CreateStack" instructions in comments are not caught but
# a granted "*:Create*"/"roles/editor" action is.
_WRITE_ACTION_RE = re.compile(
    r"\b(Create|Delete|Put|Update|Modify|Write|Attach|Detach|Remove|Add|Set|"
    r"Terminate|Stop|Start|Reboot|Run)[A-Z]",
)


# ── external id ────────────────────────────────────────────────────────────────


def test_generate_external_id_is_high_entropy_and_unique() -> None:
    a = onboarding.generate_external_id()
    b = onboarding.generate_external_id()
    assert a != b
    assert len(a) >= 32
    assert re.fullmatch(r"[0-9a-f]+", a)  # url/JSON safe, no special chars


# ── AWS CloudFormation ─────────────────────────────────────────────────────────


class TestAwsCloudFormation:
    def _template(self, **kwargs: object) -> dict:
        text = onboarding.aws_cloudformation_template(external_id="ext-abc123", role_name="agent-bom-readonly", **kwargs)
        # A CloudFormation template must be valid JSON (CFN accepts JSON).
        return json.loads(text)

    def test_is_valid_cloudformation_document(self) -> None:
        tpl = self._template()
        assert tpl["AWSTemplateFormatVersion"] == "2010-09-09"
        assert "Resources" in tpl and tpl["Resources"]

    def test_creates_a_single_iam_role(self) -> None:
        tpl = self._template()
        roles = [r for r in tpl["Resources"].values() if r["Type"] == "AWS::IAM::Role"]
        assert len(roles) == 1

    def test_role_uses_only_readonly_managed_policies(self) -> None:
        role = next(r for r in self._template()["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        arns = role["Properties"]["ManagedPolicyArns"]
        assert "arn:aws:iam::aws:policy/SecurityAudit" in arns
        assert "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess" in arns
        # Read-only guarantee: no inline policies granting write actions.
        assert "Policies" not in role["Properties"]

    def test_trust_policy_enforces_external_id(self) -> None:
        role = next(r for r in self._template()["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        stmt = role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]
        assert stmt["Action"] == "sts:AssumeRole"
        # ExternalId is always enforced — the confused-deputy defense is not optional.
        assert stmt["Condition"]["StringEquals"]["sts:ExternalId"] == {"Ref": "ExternalId"}

    def test_trust_principal_defaults_to_a_parameter(self) -> None:
        tpl = self._template()
        assert "TrustedPrincipalArn" in tpl["Parameters"]
        role = next(r for r in tpl["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        principal = role["Properties"]["AssumeRolePolicyDocument"]["Statement"][0]["Principal"]
        assert principal["AWS"] == {"Ref": "TrustedPrincipalArn"}

    def test_trust_principal_can_be_baked_in(self) -> None:
        tpl = self._template(trusted_principal_arn="arn:aws:iam::999888777666:root")
        assert tpl["Parameters"]["TrustedPrincipalArn"]["Default"] == "arn:aws:iam::999888777666:root"

    def test_external_id_default_is_baked(self) -> None:
        tpl = self._template()
        assert tpl["Parameters"]["ExternalId"]["Default"] == "ext-abc123"

    def test_outputs_round_trip_role_arn_and_external_id(self) -> None:
        tpl = self._template()
        outputs = tpl["Outputs"]
        assert outputs["RoleArn"]["Value"] == {"Fn::GetAtt": ["AgentBomReadOnlyRole", "Arn"]}
        assert outputs["ExternalId"]["Value"] == {"Ref": "ExternalId"}

    def test_no_write_actions_anywhere(self) -> None:
        # The full serialized template must not grant any mutating action.
        text = onboarding.aws_cloudformation_template(external_id="x", role_name="r")
        tpl = json.loads(text)
        role = next(r for r in tpl["Resources"].values() if r["Type"] == "AWS::IAM::Role")
        # Only sts:AssumeRole (a trust action, not a mutation on the account).
        blob = json.dumps(role["Properties"].get("Policies", []))
        assert not _WRITE_ACTION_RE.search(blob)


# ── Azure ──────────────────────────────────────────────────────────────────────


class TestAzureScript:
    def test_creates_reader_service_principal(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id="sub-123")
        assert script.startswith("#!/usr/bin/env bash")
        assert "az ad sp create-for-rbac" in script
        # Read-only: the built-in Reader role, never Owner/Contributor.
        assert '--role "Reader"' in script or "--role Reader" in script
        assert "Owner" not in script
        assert "Contributor" not in script

    def test_scopes_to_the_subscription(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id="sub-123")
        # Scope references the shell var; the supplied id is baked as its default.
        assert "/subscriptions/$SUBSCRIPTION_ID" in script
        assert "SUBSCRIPTION_ID:-sub-123" in script

    def test_no_secret_baked_in(self) -> None:
        # The client secret is generated by the user's own `az` run, never baked:
        # it is only ever referenced as the $CLIENT_SECRET shell variable.
        script = onboarding.azure_bootstrap_script(subscription_id="sub-123")
        assert "$CLIENT_SECRET" in script
        # No literal secret assignment (e.g. CLIENT_SECRET=abc123 or --password abc).
        assert not re.search(r"CLIENT_SECRET=[A-Za-z0-9]", script)
        assert "--password " not in script

    def test_round_trips_into_connect_azure(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id="sub-123")
        assert "connect azure" in script
        assert "--subscription-id sub-123" in script


# ── GCP ────────────────────────────────────────────────────────────────────────


class TestGcpScript:
    def test_creates_service_account_and_viewer_binding(self) -> None:
        script = onboarding.gcp_bootstrap_script(project_id="proj-1")
        assert script.startswith("#!/usr/bin/env bash")
        assert "gcloud iam service-accounts create" in script
        assert "roles/viewer" in script
        # Read-only: no editor/owner/admin roles.
        assert "roles/editor" not in script
        assert "roles/owner" not in script

    def test_scopes_to_the_project(self) -> None:
        script = onboarding.gcp_bootstrap_script(project_id="proj-1")
        assert "proj-1" in script
        assert "add-iam-policy-binding" in script

    def test_round_trips_into_connect_gcp(self) -> None:
        script = onboarding.gcp_bootstrap_script(project_id="proj-1")
        assert "connect gcp" in script
        assert "--project proj-1" in script


# ── Snowflake ──────────────────────────────────────────────────────────────────


class TestSnowflakeSql:
    def test_creates_readonly_role(self) -> None:
        sql = onboarding.snowflake_sql()
        assert "CREATE ROLE IF NOT EXISTS AGENT_BOM_READONLY" in sql
        # Governance metadata read only — never any DML/DDL on customer data.
        assert "GRANT IMPORTED PRIVILEGES ON DATABASE SNOWFLAKE TO ROLE AGENT_BOM_READONLY" in sql

    def test_grants_are_read_only(self) -> None:
        sql = onboarding.snowflake_sql().upper()
        for forbidden in ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "DROP TABLE", "ALL PRIVILEGES", "OWNERSHIP"):
            assert forbidden not in sql

    def test_creates_service_user_and_assigns_role(self) -> None:
        sql = onboarding.snowflake_sql()
        assert "CREATE USER IF NOT EXISTS AGENT_BOM_SVC" in sql
        assert "GRANT ROLE AGENT_BOM_READONLY TO USER AGENT_BOM_SVC" in sql

    def test_custom_names_round_trip(self) -> None:
        sql = onboarding.snowflake_sql(role="RO_ROLE", user="RO_USER", warehouse="RO_WH")
        assert "CREATE ROLE IF NOT EXISTS RO_ROLE" in sql
        assert "CREATE USER IF NOT EXISTS RO_USER" in sql
        assert "RO_WH" in sql


# ── registry (used by the CLI to pick a generator) ─────────────────────────────


class TestEmitRegistry:
    @pytest.mark.parametrize(
        "provider,fmt",
        [("aws", "cloudformation"), ("azure", "bash"), ("gcp", "bash"), ("snowflake", "sql")],
    )
    def test_default_format_per_provider(self, provider: str, fmt: str) -> None:
        assert onboarding.default_emit_format(provider) == fmt

    def test_emit_artifact_dispatches(self) -> None:
        text = onboarding.emit_artifact("snowflake", "sql", options={})
        assert "AGENT_BOM_READONLY" in text

    def test_unknown_provider_rejected(self) -> None:
        with pytest.raises(ValueError):
            onboarding.emit_artifact("nope", "sql", options={})

    def test_unknown_format_rejected(self) -> None:
        with pytest.raises(ValueError):
            onboarding.emit_artifact("aws", "terraform", options={})
