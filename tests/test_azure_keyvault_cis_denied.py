"""Regression: Azure Key Vault CIS 8.1/8.2 must NOT report PASS when the
scanner is denied data-plane access to the vaults. A vault it cannot read is
unevaluated, not compliant — returning PASS was a false compliance pass.
"""

from __future__ import annotations

import azure.identity
import azure.keyvault.keys
import azure.keyvault.secrets

from agent_bom.cloud import azure_cis_benchmark as m


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
    monkeypatch.setattr(azure.identity, "DefaultAzureCredential", lambda **kw: object())


def test_cis_8_1_all_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure.keyvault.keys, "KeyClient", _DeniedKeyClient)
    res = m._check_8_1(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence


def test_cis_8_1_readable_and_compliant_is_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure.keyvault.keys, "KeyClient", _CompliantKeyClient)
    res = m._check_8_1(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.PASS, res.evidence


class _DeniedSecretClient:
    def __init__(self, **kw):
        pass

    def list_properties_of_secrets(self):
        raise Exception("(Forbidden) Caller is not authorized")


def test_cis_8_2_all_vaults_denied_is_error_not_pass(monkeypatch):
    _patch_identity(monkeypatch)
    monkeypatch.setattr(azure.keyvault.secrets, "SecretClient", _DeniedSecretClient)
    res = m._check_8_2(_KVMgmt(), "sub-1")
    assert res.status == m.CheckStatus.ERROR, f"expected ERROR, got {res.status}: {res.evidence}"
    assert "data-plane access denied" in res.evidence
