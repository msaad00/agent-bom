"""Regression: Azure Key Vault CIS 8.1/8.2 must NOT report PASS when the
scanner is denied data-plane access to the vaults. A vault it cannot read is
unevaluated, not compliant — returning PASS was a false compliance pass.
"""

from __future__ import annotations

import pytest

# The checks import azure.* lazily inside the function; these tests patch those
# symbols, so the SDK must be importable. Skip cleanly where it is not installed.
azure_identity = pytest.importorskip("azure.identity")
azure_keys = pytest.importorskip("azure.keyvault.keys")
azure_secrets = pytest.importorskip("azure.keyvault.secrets")

from agent_bom.cloud import azure_cis_benchmark as m  # noqa: E402


class _Vault:
    def __init__(self, name):
        self.name = name


class _KVMgmt:
    class vaults:
        @staticmethod
        def list():
            return [_Vault("v1"), _Vault("v2")]


class _DeniedKeyClient:
    def __init__(self, **kw):
        pass

    def list_properties_of_keys(self):
        raise Exception("(Forbidden) Caller is not authorized to perform action on resource")


class _CompliantKeyClient:
    def __init__(self, **kw):
        pass

    def list_properties_of_keys(self):
        class _K:
            name = "k1"
            expires_on = "2027-01-01"
        return [_K()]


def _patch_identity(monkeypatch):
    monkeypatch.setattr(azure_identity, "DefaultAzureCredential", lambda **kw: object())


def test_cis_8_1_all_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_keys, "KeyClient", _DeniedKeyClient)
    res = m._check_8_1(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence


def test_cis_8_1_readable_and_compliant_is_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_keys, "KeyClient", _CompliantKeyClient)
    res = m._check_8_1(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.PASS, res.evidence


class _DeniedSecretClient:
    def __init__(self, **kw):
        pass

    def list_properties_of_secrets(self):
        raise Exception("(Forbidden) Caller is not authorized")


def test_cis_8_2_all_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_secrets, "SecretClient", _DeniedSecretClient)
    res = m._check_8_2(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence


# --- RBAC-vault checks 8.4 / 8.5 and content-type check 8.6 -----------------
# These had the same swallow-to-PASS bug and must also surface ERROR on denial.


class _RbacVault:
    def __init__(self, name):
        self.name = name
        self.id = (
            f"/subscriptions/sub-1/resourceGroups/rg1/providers/"
            f"Microsoft.KeyVault/vaults/{name}"
        )


class _RbacKVMgmt:
    """Management client whose vaults are all RBAC-model."""

    class vaults:
        @staticmethod
        def list():
            return [_RbacVault("v1"), _RbacVault("v2")]

        @staticmethod
        def get(resource_group, vault_name):
            props = type("P", (), {"enable_rbac_authorization": True})()
            return type("V", (), {"properties": props})()


def test_cis_8_4_all_rbac_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_keys, "KeyClient", _DeniedKeyClient)
    res = m._check_8_4(_RbacKVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence


def test_cis_8_5_all_rbac_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_secrets, "SecretClient", _DeniedSecretClient)
    res = m._check_8_5(_RbacKVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence


def test_cis_8_6_all_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure_secrets, "SecretClient", _DeniedSecretClient)
    res = m._check_8_6(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence
