"""`agent-bom connect <provider> --emit` writes ready-to-run deploy artifacts.

The emit path is provisioning-time (before the operator has credentials), so it
must NOT require the establish flags. It prints the artifact to stdout (pipe-
friendly) or writes it to ``--out``, and prints the round-trip connect command
to stderr so stdout stays a clean artifact.
"""

from __future__ import annotations

import json

from click.testing import CliRunner


def _main():
    from agent_bom.cli import main

    return main


def _run(args: list[str], **kw):
    # Click 8.2 captures stdout/stderr separately, so stdout stays a clean artifact.
    return CliRunner().invoke(_main(), args, **kw)


class TestAwsEmit:
    def test_emits_valid_cloudformation_to_stdout(self) -> None:
        r = _run(["connect", "aws", "--emit", "cloudformation"])
        assert r.exit_code == 0, r.output
        tpl = json.loads(r.stdout)  # stdout is a pure, parseable template
        assert tpl["Resources"]["AgentBomReadOnlyRole"]["Type"] == "AWS::IAM::Role"

    def test_bakes_trust_principal_and_role_name(self) -> None:
        r = _run(
            [
                "connect",
                "aws",
                "--emit",
                "cloudformation",
                "--trust-principal",
                "arn:aws:iam::999888777666:root",
                "--role-name",
                "my-ro-role",
                "--external-id",
                "EXT-XYZ",
            ]
        )
        assert r.exit_code == 0, r.output
        tpl = json.loads(r.stdout)
        assert tpl["Parameters"]["TrustedPrincipalArn"]["Default"] == "arn:aws:iam::999888777666:root"
        assert tpl["Parameters"]["RoleName"]["Default"] == "my-ro-role"
        assert tpl["Parameters"]["ExternalId"]["Default"] == "EXT-XYZ"

    def test_writes_to_out_file(self, tmp_path) -> None:
        out = tmp_path / "role.json"
        r = _run(["connect", "aws", "--emit", "cloudformation", "--out", str(out)])
        assert r.exit_code == 0, r.output
        tpl = json.loads(out.read_text())
        assert tpl["AWSTemplateFormatVersion"] == "2010-09-09"
        # Round-trip guidance points back at connect aws.
        assert "connect aws" in r.stderr

    def test_default_format_when_flag_has_no_value(self) -> None:
        # `--emit` with no explicit format uses the provider default.
        r = _run(["connect", "aws", "--emit"])
        assert r.exit_code == 0, r.output
        assert json.loads(r.stdout)["AWSTemplateFormatVersion"] == "2010-09-09"

    def test_emit_does_not_require_establish_flags(self) -> None:
        # No --role-arn/--external-id needed to emit (provisioning-time).
        r = _run(["connect", "aws", "--emit", "cloudformation"])
        assert r.exit_code == 0
        assert "provide both" not in r.stderr.lower()


class TestOtherProviderEmit:
    def test_azure_emits_reader_script(self) -> None:
        r = _run(["connect", "azure", "--emit", "--subscription-id", "sub-1"])
        assert r.exit_code == 0, r.output
        assert "az ad sp create-for-rbac" in r.stdout
        assert "sub-1" in r.stdout

    def test_gcp_emits_viewer_script(self) -> None:
        r = _run(["connect", "gcp", "--emit", "--project", "proj-1"])
        assert r.exit_code == 0, r.output
        assert "roles/viewer" in r.stdout
        assert "proj-1" in r.stdout

    def test_snowflake_emits_readonly_sql(self) -> None:
        r = _run(["connect", "snowflake", "--emit"])
        assert r.exit_code == 0, r.output
        assert "CREATE ROLE IF NOT EXISTS AGENT_BOM_READONLY" in r.stdout

    def test_snowflake_custom_role_name(self) -> None:
        r = _run(["connect", "snowflake", "--emit", "sql", "--role", "RO_ROLE"])
        assert r.exit_code == 0, r.output
        assert "CREATE ROLE IF NOT EXISTS RO_ROLE" in r.stdout


class TestEmitValidation:
    def test_unsupported_format_is_rejected(self) -> None:
        r = _run(["connect", "aws", "--emit", "terraform"])
        assert r.exit_code != 0

    def test_help_documents_emit(self) -> None:
        r = _run(["connect", "aws", "--help"])
        assert r.exit_code == 0
        assert "--emit" in r.stdout
