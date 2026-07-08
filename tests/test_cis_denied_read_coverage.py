"""Regression: CIS checks must fail-closed on per-resource permission denial.

A "list-but-not-get" read-only split (the role can enumerate resources but is
denied the per-resource read) previously left the check at its default
``status=PASS`` because the per-resource ``AccessDenied`` was swallowed and the
failure accumulator stayed empty. That minted a false "compliant" for a scope
that was never actually inspected.

These tests assert the strict GRC contract across AWS, GCP, and Azure:
  * every per-resource read denied  -> ERROR (never PASS), evidence names perm;
  * any per-resource read denied    -> ERROR (partial coverage cannot PASS);
  * resources exist and all clean   -> PASS;
  * a real violation                -> FAIL;
  * genuinely zero resources        -> PASS (not ERROR — nothing was denied).
"""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

from agent_bom.cloud.aws_cis_benchmark import (
    CheckStatus,
    _check_1_16,
    _check_2_1_2,
)


def _denied_exc() -> Exception:
    """A botocore-style AccessDenied ClientError shape."""
    exc = Exception("An error occurred (AccessDenied) when calling the operation")
    exc.response = {"Error": {"Code": "AccessDenied"}}  # type: ignore[attr-defined]
    return exc


# ---------------------------------------------------------------------------
# AWS
# ---------------------------------------------------------------------------


class TestAwsCheck212DeniedReads:
    def test_all_reads_denied_is_error_not_pass(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "b1"}, {"Name": "b2"}]}
        client.get_bucket_encryption.side_effect = _denied_exc()
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.ERROR, result.evidence
        assert "permission denied" in result.evidence.lower()
        assert "s3:GetEncryptionConfiguration" in result.evidence

    def test_all_clear_is_pass(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "b1"}]}
        client.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.PASS, result.evidence

    def test_real_violation_still_fails(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "open-bucket"}]}
        exc = Exception("ServerSideEncryptionConfigurationNotFoundError")
        exc.response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
        client.get_bucket_encryption.side_effect = exc
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.FAIL, result.evidence
        assert "open-bucket" in result.evidence

    def test_zero_buckets_is_pass_not_error(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": []}
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.PASS, result.evidence

    def test_mixed_some_denied_some_clean_is_error_not_pass(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "ok"}, {"Name": "denied"}]}

        def _side_effect(Bucket):  # noqa: N803 — botocore kwarg name
            if Bucket == "denied":
                raise _denied_exc()
            return {"ServerSideEncryptionConfiguration": {}}

        client.get_bucket_encryption.side_effect = _side_effect
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.ERROR, result.evidence
        assert "Incomplete evaluation" in result.evidence
        assert "s3:GetEncryptionConfiguration" in result.evidence


class TestAwsCheck116DeniedReads:
    def _client_with_one_policy(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"Policies": [{"Arn": "arn:aws:iam::1:policy/p1", "PolicyName": "p1", "DefaultVersionId": "v1"}]}
        ]
        client.get_paginator.return_value = paginator
        return client

    def test_all_policy_reads_denied_is_error_not_pass(self):
        client = self._client_with_one_policy()
        client.get_policy_version.side_effect = _denied_exc()
        result = _check_1_16(client)
        assert result.status == CheckStatus.ERROR, result.evidence
        assert "iam:GetPolicyVersion" in result.evidence

    def test_readable_non_admin_is_pass(self):
        client = self._client_with_one_policy()
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}]}}
        }
        result = _check_1_16(client)
        assert result.status == CheckStatus.PASS, result.evidence

    def test_admin_policy_still_fails(self):
        client = self._client_with_one_policy()
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
        }
        result = _check_1_16(client)
        assert result.status == CheckStatus.FAIL, result.evidence


# ---------------------------------------------------------------------------
# GCP
# ---------------------------------------------------------------------------


def _install_mock_gcp_storage(buckets):
    """Install a fake google.cloud.storage whose Client lists *buckets*."""
    google_mod = sys.modules.get("google") or types.ModuleType("google")
    sys.modules["google"] = google_mod
    google_cloud = sys.modules.get("google.cloud") or types.ModuleType("google.cloud")
    sys.modules["google.cloud"] = google_cloud
    google_mod.cloud = google_cloud  # type: ignore[attr-defined]

    storage_mod = types.ModuleType("google.cloud.storage")
    client = MagicMock()
    client.return_value.list_buckets.return_value = buckets
    storage_mod.Client = client  # type: ignore[attr-defined]
    google_cloud.storage = storage_mod  # type: ignore[attr-defined]
    sys.modules["google.cloud.storage"] = storage_mod


class TestGcpCheck51DeniedReads:
    def _import_check(self):
        from agent_bom.cloud.gcp_cis_benchmark import _check_5_1

        return _check_5_1

    def test_all_iam_reads_denied_is_error_not_pass(self):
        bucket = MagicMock()
        bucket.name = "b1"
        bucket.get_iam_policy.side_effect = Exception("403 Forbidden: permission denied")
        _install_mock_gcp_storage([bucket])
        result = self._import_check()("my-project")
        assert result.status == CheckStatus.ERROR, result.evidence
        assert "storage.buckets.getIamPolicy" in result.evidence

    def test_all_clear_is_pass(self):
        bucket = MagicMock()
        bucket.name = "b1"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["user:a@example.com"]}]
        bucket.get_iam_policy.return_value = policy
        _install_mock_gcp_storage([bucket])
        result = self._import_check()("my-project")
        assert result.status == CheckStatus.PASS, result.evidence

    def test_public_bucket_still_fails(self):
        bucket = MagicMock()
        bucket.name = "public"
        policy = MagicMock()
        policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
        bucket.get_iam_policy.return_value = policy
        _install_mock_gcp_storage([bucket])
        result = self._import_check()("my-project")
        assert result.status == CheckStatus.FAIL, result.evidence
        assert "public" in result.evidence


# ---------------------------------------------------------------------------
# Azure
# ---------------------------------------------------------------------------


def _sql_server(name="s1"):
    srv = MagicMock()
    srv.name = name
    srv.id = f"/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Sql/servers/{name}"
    return srv


class TestAzureCheck411DeniedReads:
    def _import_check(self):
        from agent_bom.cloud.azure_cis_benchmark import _check_4_1_1

        return _check_4_1_1

    def test_all_reads_denied_is_error_not_pass(self):
        sql = MagicMock()
        sql.servers.list.return_value = [_sql_server()]
        sql.server_blob_auditing_policies.get.side_effect = Exception("(Forbidden) Caller is not authorized")
        result = self._import_check()(sql)
        assert result.status == CheckStatus.ERROR, result.evidence
        assert "auditingSettings" in result.evidence

    def test_all_clear_is_pass(self):
        sql = MagicMock()
        sql.servers.list.return_value = [_sql_server()]
        sql.server_blob_auditing_policies.get.return_value = MagicMock(state="Enabled")
        result = self._import_check()(sql)
        assert result.status == CheckStatus.PASS, result.evidence

    def test_real_violation_still_fails(self):
        sql = MagicMock()
        sql.servers.list.return_value = [_sql_server()]
        sql.server_blob_auditing_policies.get.return_value = MagicMock(state="Disabled")
        result = self._import_check()(sql)
        assert result.status == CheckStatus.FAIL, result.evidence


class TestAzureCheck93TlsCoverage:
    def _import_check(self):
        from agent_bom.cloud.azure_cis_benchmark import _check_9_3

        return _check_9_3

    def _webapp(self, name="app1"):
        app = MagicMock()
        app.name = name
        app.id = f"/subscriptions/x/resourceGroups/rg1/providers/Microsoft.Web/sites/{name}"
        return app

    def test_all_config_reads_denied_is_error_not_pass(self):
        web = MagicMock()
        web.web_apps.list.return_value = [self._webapp()]
        web.web_apps.get_configuration.side_effect = Exception("(Forbidden) not authorized")
        result = self._import_check()(web)
        assert result.status == CheckStatus.ERROR, result.evidence

    def test_unset_min_tls_is_fail_not_pass(self):
        # Regression for the "only flags when min_tls truthy" bug: an app that
        # does not report a minimum TLS version is not demonstrably compliant.
        web = MagicMock()
        web.web_apps.list.return_value = [self._webapp()]
        web.web_apps.get_configuration.return_value = MagicMock(min_tls_version="")
        result = self._import_check()(web)
        assert result.status == CheckStatus.FAIL, result.evidence

    def test_tls_12_is_pass(self):
        web = MagicMock()
        web.web_apps.list.return_value = [self._webapp()]
        web.web_apps.get_configuration.return_value = MagicMock(min_tls_version="1.2")
        result = self._import_check()(web)
        assert result.status == CheckStatus.PASS, result.evidence
