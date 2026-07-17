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

# A syntactically valid Azure subscription id (GUID) — real subscription ids are
# always GUIDs, so the artifacts validate the shape and reject anything else.
_VALID_AZURE_SUB = "11111111-2222-3333-4444-555555555555"


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
        # The managed-policy set must be EXACTLY the two read-only ARNs — not
        # merely contain them (a stray AdministratorAccess would then slip past).
        assert set(arns) == {
            "arn:aws:iam::aws:policy/SecurityAudit",
            "arn:aws:iam::aws:policy/job-function/ViewOnlyAccess",
        }
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
        # The ENTIRE serialized template — not just an (always-empty) inline
        # Policies block — must be free of any granted mutating action. The only
        # action present is sts:AssumeRole (a trust action, not an account
        # mutation), which the regex intentionally does not match.
        text = onboarding.aws_cloudformation_template(external_id="x", role_name="r")
        assert not _WRITE_ACTION_RE.search(text)


# ── Azure ──────────────────────────────────────────────────────────────────────


class TestAzureScript:
    def test_creates_reader_service_principal(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        assert script.startswith("#!/usr/bin/env bash")
        assert "az ad sp create-for-rbac" in script
        # Read-only: the built-in Reader role, never Owner/Contributor.
        assert '--role "Reader"' in script or "--role Reader" in script
        assert "Owner" not in script
        assert "Contributor" not in script

    def test_scopes_to_the_subscription(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        # Scope references the shell var; the supplied id is baked as its default.
        assert "/subscriptions/$SUBSCRIPTION_ID" in script
        assert f"SUBSCRIPTION_ID:-{_VALID_AZURE_SUB}" in script

    def test_no_secret_baked_in(self) -> None:
        # The client secret is generated by the user's own `az` run, never baked:
        # it is only ever referenced as the $CLIENT_SECRET shell variable.
        script = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        assert "$CLIENT_SECRET" in script
        # No literal secret assignment (e.g. CLIENT_SECRET=abc123 or --password abc).
        assert not re.search(r"CLIENT_SECRET=[A-Za-z0-9]", script)
        assert "--password " not in script

    def test_round_trips_into_connect_azure(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        assert "connect azure" in script
        assert f"--subscription-id {_VALID_AZURE_SUB}" in script


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


# ── depth: baseline vs deep-scan + opt-in DSPM (issue #3736) ─────────────────────


def _aws_role(text: str) -> dict:
    tpl = json.loads(text)
    return next(r for r in tpl["Resources"].values() if r["Type"] == "AWS::IAM::Role")


class TestAwsDeepScanDepth:
    """Depth is an explicit opt-in threaded into the emitted artifact. Baseline
    stays SecurityAudit+ViewOnly only (least privilege); deep-scan adds the same
    read-only content-read statements as ``deploy/terraform/connect-aws/deep-scan.tf``;
    DSPM S3 object read is separately opt-in and bucket-scoped."""

    def test_baseline_has_no_inline_policies(self) -> None:
        role = _aws_role(onboarding.aws_cloudformation_template(external_id="x", role_name="r"))
        assert "Policies" not in role["Properties"]

    def test_deep_scan_adds_readonly_content_reads(self) -> None:
        text = onboarding.aws_cloudformation_template(external_id="x", role_name="r", enable_deep_scan_reads=True)
        role = _aws_role(text)
        policies = role["Properties"]["Policies"]
        actions = {a for p in policies for s in p["PolicyDocument"]["Statement"] for a in _as_list(s["Action"])}
        # Mirrors deep-scan.tf: Lambda code, ECR pull, Inspector, CIS contacts, Bedrock.
        assert "lambda:GetFunction" in actions
        assert "ecr:GetDownloadUrlForLayer" in actions
        assert "inspector2:ListFindings" in actions
        assert "account:GetContactInformation" in actions
        assert "bedrock:GetAgent" in actions
        # No S3 object read unless DSPM buckets are supplied.
        assert "s3:GetObject" not in actions
        # Still read-only — no mutating verb anywhere in the serialized template.
        assert not _WRITE_ACTION_RE.search(text)

    def test_dspm_grants_bucket_scoped_object_read(self) -> None:
        text = onboarding.aws_cloudformation_template(
            external_id="x",
            role_name="r",
            enable_deep_scan_reads=True,
            dspm_s3_bucket_arns=["arn:aws:s3:::my-lake"],
        )
        role = _aws_role(text)
        dspm = [s for p in role["Properties"]["Policies"] for s in p["PolicyDocument"]["Statement"] if s.get("Sid") == "DspmS3ObjectSample"]
        assert dspm, "expected a DSPM S3 statement"
        assert set(_as_list(dspm[0]["Action"])) == {"s3:GetObject", "s3:ListBucket"}
        # Scoped to the named bucket + its objects — never a wildcard.
        assert set(dspm[0]["Resource"]) == {"arn:aws:s3:::my-lake", "arn:aws:s3:::my-lake/*"}

    def test_dspm_implies_deep_scan(self) -> None:
        # Supplying DSPM buckets alone still yields the deep-scan policy container,
        # matching the terraform (whole deep_scan policy count-gated on the flag).
        text = onboarding.aws_cloudformation_template(external_id="x", role_name="r", dspm_s3_bucket_arns=["arn:aws:s3:::data-lake"])
        role = _aws_role(text)
        assert "Policies" in role["Properties"]

    def test_dspm_rejects_hostile_bucket_arn(self) -> None:
        with pytest.raises(ValueError):
            onboarding.aws_cloudformation_template(
                external_id="x", role_name="r", dspm_s3_bucket_arns=['arn:aws:s3:::b", "Effect": "Allow']
            )


class TestAzureDeepScanDepth:
    def test_baseline_is_reader_only(self) -> None:
        text = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        assert "Key Vault Reader" not in text
        assert "AcrPull" not in text

    def test_deep_scan_adds_dataplane_readers(self) -> None:
        text = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB, enable_deep_scan_reads=True)
        assert "az role assignment create" in text
        assert "Key Vault Reader" in text
        assert "AcrPull" in text
        assert not _WRITE_ACTION_RE.search(text)


class TestGcpDeepScanDepth:
    def test_baseline_has_no_artifact_registry(self) -> None:
        text = onboarding.gcp_bootstrap_script(project_id="proj-123")
        assert "roles/artifactregistry.reader" not in text

    def test_deep_scan_adds_artifact_registry_reader(self) -> None:
        text = onboarding.gcp_bootstrap_script(project_id="proj-123", enable_deep_scan_reads=True)
        assert "roles/artifactregistry.reader" in text
        assert not _WRITE_ACTION_RE.search(text)


class TestEmitDepthThreading:
    def test_emit_aws_threads_deep_scan_and_dspm(self) -> None:
        text = onboarding.emit_artifact(
            "aws",
            "cloudformation",
            options={"enable_deep_scan_reads": "true", "dspm_s3_bucket_arns": "arn:aws:s3:::lake, arn:aws:s3:::logs"},
        )
        role = _aws_role(text)
        actions = {a for p in role["Properties"]["Policies"] for s in p["PolicyDocument"]["Statement"] for a in _as_list(s["Action"])}
        assert "lambda:GetFunction" in actions
        assert "s3:GetObject" in actions
        resources = {
            r
            for p in role["Properties"]["Policies"]
            for s in p["PolicyDocument"]["Statement"]
            if s.get("Sid") == "DspmS3ObjectSample"
            for r in s["Resource"]
        }
        assert "arn:aws:s3:::logs" in resources

    def test_emit_aws_baseline_default_is_least_privilege(self) -> None:
        role = _aws_role(onboarding.emit_artifact("aws", "cloudformation", options={}))
        assert "Policies" not in role["Properties"]

    def test_emit_azure_threads_deep_scan(self) -> None:
        text = onboarding.emit_artifact("azure", "bash", options={"subscription_id": _VALID_AZURE_SUB, "enable_deep_scan_reads": "1"})
        assert "Key Vault Reader" in text

    def test_emit_gcp_threads_deep_scan(self) -> None:
        text = onboarding.emit_artifact("gcp", "bash", options={"project_id": "proj-123", "enable_deep_scan_reads": "yes"})
        assert "roles/artifactregistry.reader" in text


def _as_list(value: object) -> list:
    return list(value) if isinstance(value, list) else [value]


class TestSnowflakeSpcs:
    """The wizard/CLI can generate the SPCS native-app install inline, reusing the
    shipped ``deploy/snowflake/native-app/`` package (issue #3736)."""

    def test_spcs_recipe_reuses_shipped_package(self) -> None:
        text = onboarding.snowflake_spcs_setup()
        assert "deploy/snowflake/native-app" in text
        assert "snow app run --project deploy/snowflake/native-app" in text
        assert "Artifact:" in text
        assert "Next step:" in text
        assert "customer_grants_template.sql" in text
        assert "auth_keypair_setup.sql" in text
        assert "Upload deploy/snowflake/native-app" not in text
        assert "INSTALL_FROM_MARKETPLACE" not in text

    def test_spcs_bakes_account(self) -> None:
        assert "ORG-ACCT" in onboarding.snowflake_spcs_setup(account="ORG-ACCT")

    def test_emit_snowflake_spcs_mode(self) -> None:
        text = onboarding.emit_artifact("snowflake", "sql", options={"mode": "spcs"})
        assert "snow app run --project deploy/snowflake/native-app" in text

    def test_emit_snowflake_role_mode_is_default(self) -> None:
        text = onboarding.emit_artifact("snowflake", "sql", options={})
        assert "CREATE ROLE IF NOT EXISTS" in text
        assert "snow app run --project" not in text


# ── adversarial input hardening (injection defense) ─────────────────────────────


class TestSnowflakeInjectionRejected:
    """Snowflake identifiers are interpolated UNQUOTED into an ACCOUNTADMIN-run
    script; a hostile role/user/warehouse must be rejected, never emitted."""

    _PAYLOAD = "X; GRANT ROLE ACCOUNTADMIN TO USER attacker; --"

    @pytest.mark.parametrize("field", ["role", "user", "warehouse"])
    def test_identifier_injection_rejected(self, field: str) -> None:
        with pytest.raises(ValueError):
            onboarding.snowflake_sql(**{field: self._PAYLOAD})

    @pytest.mark.parametrize(
        "bad",
        [
            "X; DROP TABLE foo",
            "role name",  # embedded space
            'role"quote',
            "role'quote",
            "1role",  # must start with a letter/underscore
            "role$$; --",
            "",  # empty is not a valid identifier
            "A" * 256,  # exceeds Snowflake's identifier length cap
        ],
    )
    def test_malformed_identifier_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            onboarding.snowflake_sql(role=bad)

    def test_emit_artifact_surfaces_rejection_not_corrupted_script(self) -> None:
        # The dispatch path (what the CLI calls) must raise, not emit a script
        # carrying the injected ACCOUNTADMIN grant.
        with pytest.raises(ValueError):
            onboarding.emit_artifact("snowflake", "sql", options={"role": self._PAYLOAD})

    def test_valid_identifiers_still_accepted(self) -> None:
        sql = onboarding.snowflake_sql(role="RO_ROLE", user="RO_USER", warehouse="RO_WH")
        assert "CREATE ROLE IF NOT EXISTS RO_ROLE" in sql
        # No injected privilege escalation grant (the "Run as ACCOUNTADMIN"
        # comment is expected; a GRANT ... ACCOUNTADMIN ... is not).
        assert "GRANT ROLE ACCOUNTADMIN" not in sql.upper()


class TestAzureInjectionRejected:
    """The subscription id is interpolated into a bash script; a hostile value
    must be rejected on shape, never break out of the shell context."""

    def test_bash_injection_subscription_rejected(self) -> None:
        with pytest.raises(ValueError):
            onboarding.azure_bootstrap_script(subscription_id="foo}; rm -rf /tmp/x #")

    @pytest.mark.parametrize(
        "bad",
        [
            "foo}; rm -rf /tmp/x #",
            "$(whoami)",
            "`id`",
            "sub-123",  # not a GUID
            "11111111-2222-3333-4444-55555555555",  # too short
        ],
    )
    def test_malformed_subscription_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            onboarding.azure_bootstrap_script(subscription_id=bad)

    def test_emit_artifact_surfaces_rejection(self) -> None:
        with pytest.raises(ValueError):
            onboarding.emit_artifact("azure", "bash", options={"subscription_id": "foo}; rm -rf /tmp/x #"})

    def test_valid_guid_accepted_without_metacharacters(self) -> None:
        script = onboarding.azure_bootstrap_script(subscription_id=_VALID_AZURE_SUB)
        assert _VALID_AZURE_SUB in script
        for meta in (";", "`", "$(", "&&", "|", "\n{"):
            assert f"{_VALID_AZURE_SUB}{meta}" not in script

    def test_empty_subscription_keeps_placeholder(self) -> None:
        # No value supplied: emit the human-editable placeholder, do not raise.
        script = onboarding.azure_bootstrap_script(subscription_id="")
        assert "<YOUR_SUBSCRIPTION_ID>" in script


class TestGcpInjectionRejected:
    """The project id is interpolated into a bash script; a hostile value must be
    rejected on shape, never break out of the shell context."""

    def test_bash_injection_project_rejected(self) -> None:
        with pytest.raises(ValueError):
            onboarding.gcp_bootstrap_script(project_id="foo}; rm -rf /tmp/x #")

    @pytest.mark.parametrize(
        "bad",
        [
            "foo}; rm -rf /tmp/x #",
            "$(whoami)",
            "`id`",
            "Proj-1",  # uppercase not allowed in a GCP project id
            "ab",  # too short
            "-startswithdash",
        ],
    )
    def test_malformed_project_rejected(self, bad: str) -> None:
        with pytest.raises(ValueError):
            onboarding.gcp_bootstrap_script(project_id=bad)

    def test_emit_artifact_surfaces_rejection(self) -> None:
        with pytest.raises(ValueError):
            onboarding.emit_artifact("gcp", "bash", options={"project_id": "foo}; rm -rf /tmp/x #"})

    def test_valid_project_accepted_without_metacharacters(self) -> None:
        script = onboarding.gcp_bootstrap_script(project_id="proj-1")
        assert "proj-1" in script
        for meta in (";", "`", "$(", "&&", "|", "\n{"):
            assert f"proj-1{meta}" not in script

    def test_empty_project_keeps_placeholder(self) -> None:
        script = onboarding.gcp_bootstrap_script(project_id="")
        assert "<YOUR_PROJECT_ID>" in script
