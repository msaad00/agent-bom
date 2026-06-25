"""Credential-based provider detection — :mod:`agent_bom.cloud.auth_probe`.

Pins that providers are detected by actual credential SOURCES (env vars, IRSA /
workload-identity token files, shared config files, local SDK resolution) and
NOT by a CLI binary on ``PATH``. This closes both mis-detection modes the old
``shutil.which`` check had:

- the hosted/EKS collector with IRSA but no ``aws`` CLI is now detected
  (false negative fixed);
- an ``aws`` CLI present with zero credentials is no longer a false positive.

Detection makes no network call — every probe here is env/file/local-resolver
only — so these tests run with no cloud reachable.
"""

from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

from agent_bom.cloud import auth_probe

# Env vars that could leak a real credential source into the test environment.
_CLEARED = [
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
    "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AZURE_CLIENT_ID",
    "AZURE_CLIENT_SECRET",
    "AZURE_CLIENT_CERTIFICATE_PATH",
    "AZURE_TENANT_ID",
    "AZURE_FEDERATED_TOKEN_FILE",
    "MSI_ENDPOINT",
    "IDENTITY_ENDPOINT",
    "AZURE_POD_IDENTITY_AUTHORITY_HOST",
    "AZURE_CONFIG_DIR",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AGENT_BOM_GCP_IMPERSONATE_SA",
    "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
    "CLOUDSDK_CONFIG",
    "GCE_METADATA_HOST",
    "GCE_METADATA_ROOT",
    "GCE_METADATA_IP",
    "SNOWFLAKE_ACCOUNT",
    "SNOWFLAKE_USER",
    "SNOWFLAKE_PRIVATE_KEY_PATH",
]


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """Strip every credential env var, point HOME at an empty dir, neuter SDKs."""
    for name in _CLEARED:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    # Force the SDK resolvers to report "nothing resolved" so a real ambient
    # credential on the test host cannot make a probe pass.
    fake_boto3 = SimpleNamespace(Session=lambda: SimpleNamespace(get_credentials=lambda: None))
    monkeypatch.setitem(sys.modules, "boto3", fake_boto3)

    def _no_google_default():
        raise RuntimeError("no ADC")

    fake_google_auth = SimpleNamespace(default=_no_google_default)
    monkeypatch.setitem(sys.modules, "google.auth", fake_google_auth)
    return monkeypatch


# ── AWS ──────────────────────────────────────────────────────────────────────


class TestAWS:
    def test_irsa_token_file_detected_without_cli(self, clean_env, tmp_path):
        """The hosted collector case: IRSA token, no ``aws`` CLI → AWS detected."""
        token = tmp_path / "token"
        token.write_text("jwt")
        clean_env.setenv("AWS_WEB_IDENTITY_TOKEN_FILE", str(token))
        clean_env.setenv("AWS_ROLE_ARN", "arn:aws:iam::123:role/collector")
        # Even if no `aws` binary exists, credentials are present.
        clean_env.setattr("shutil.which", lambda _name: None)

        has, source = auth_probe.provider_has_credentials("aws")
        assert has is True
        assert "AWS_WEB_IDENTITY_TOKEN_FILE" in source

    def test_access_key_env_detected(self, clean_env):
        clean_env.setenv("AWS_ACCESS_KEY_ID", "AKIA...")
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is True
        assert "AWS_ACCESS_KEY_ID" in source

    def test_container_role_uri_detected(self, clean_env):
        clean_env.setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "/v2/creds")
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is True
        assert "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI" in source

    def test_shared_credentials_file_detected(self, clean_env, tmp_path):
        creds = tmp_path / "credentials"
        creds.write_text("[default]\naws_access_key_id=x\n")
        clean_env.setenv("AWS_SHARED_CREDENTIALS_FILE", str(creds))
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is True
        assert "shared credentials file" in source

    def test_cli_present_zero_creds_is_not_false_positive(self, clean_env):
        """``aws`` CLI on PATH but no credentials → NOT a positive detection."""
        clean_env.setattr("shutil.which", lambda name: "/usr/bin/aws" if name == "aws" else None)
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is False
        # The CLI presence is surfaced only as a last-resort hint, not creds.
        assert "cli present" in source

    def test_no_creds_no_cli(self, clean_env):
        clean_env.setattr("shutil.which", lambda _name: None)
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is False
        assert source == "no credentials"


# ── Azure ────────────────────────────────────────────────────────────────────


class TestAzure:
    def test_workload_identity_detected(self, clean_env, tmp_path):
        token = tmp_path / "azure-token"
        token.write_text("jwt")
        clean_env.setenv("AZURE_FEDERATED_TOKEN_FILE", str(token))
        has, source = auth_probe.provider_has_credentials("azure")
        assert has is True
        assert "AZURE_FEDERATED_TOKEN_FILE" in source

    def test_service_principal_detected(self, clean_env):
        clean_env.setenv("AZURE_CLIENT_ID", "cid")
        clean_env.setenv("AZURE_CLIENT_SECRET", "secret")
        clean_env.setenv("AZURE_TENANT_ID", "tid")
        has, source = auth_probe.provider_has_credentials("azure")
        assert has is True
        assert "service principal" in source

    def test_no_creds(self, clean_env):
        clean_env.setattr("shutil.which", lambda _name: None)
        has, _source = auth_probe.provider_has_credentials("azure")
        assert has is False


# ── GCP ──────────────────────────────────────────────────────────────────────


class TestGCP:
    def test_application_credentials_env_detected(self, clean_env, tmp_path):
        key = tmp_path / "sa.json"
        key.write_text("{}")
        clean_env.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))
        has, source = auth_probe.provider_has_credentials("gcp")
        assert has is True
        assert "GOOGLE_APPLICATION_CREDENTIALS" in source

    def test_adc_well_known_file_detected(self, clean_env, tmp_path):
        cfg = tmp_path / "gcloud"
        cfg.mkdir()
        (cfg / "application_default_credentials.json").write_text("{}")
        clean_env.setenv("CLOUDSDK_CONFIG", str(cfg))
        has, source = auth_probe.provider_has_credentials("gcp")
        assert has is True
        assert "ADC file" in source

    def test_impersonation_env_detected(self, clean_env):
        clean_env.setenv("AGENT_BOM_GCP_IMPERSONATE_SA", "sa@proj.iam.gserviceaccount.com")
        has, source = auth_probe.provider_has_credentials("gcp")
        assert has is True
        assert "impersonation" in source

    def test_no_creds(self, clean_env):
        clean_env.setattr("shutil.which", lambda _name: None)
        has, _source = auth_probe.provider_has_credentials("gcp")
        assert has is False


# ── Snowflake ────────────────────────────────────────────────────────────────


class TestSnowflake:
    def test_keypair_detected(self, clean_env, tmp_path):
        key = tmp_path / "rsa_key.p8"
        key.write_text("key")
        clean_env.setenv("SNOWFLAKE_ACCOUNT", "acct")
        clean_env.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", str(key))
        has, source = auth_probe.provider_has_credentials("snowflake")
        assert has is True
        assert "key-pair" in source

    def test_account_without_user_or_key_not_detected(self, clean_env):
        clean_env.setenv("SNOWFLAKE_ACCOUNT", "acct")
        clean_env.setattr("shutil.which", lambda _name: None)
        has, _source = auth_probe.provider_has_credentials("snowflake")
        assert has is False


# ── contract ─────────────────────────────────────────────────────────────────


class TestContract:
    def test_unknown_provider_never_raises(self):
        has, source = auth_probe.provider_has_credentials("nope")
        assert has is False
        assert source == "unknown provider"

    def test_probe_exception_degrades_to_false(self, clean_env, monkeypatch):
        def _boom() -> str:
            raise RuntimeError("kaboom")

        monkeypatch.setitem(auth_probe._PROBES, "aws", _boom)
        clean_env.setattr("shutil.which", lambda _name: None)
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is False
        assert source == "no credentials"

    def test_source_string_returned_for_ui(self, clean_env):
        clean_env.setenv("AWS_PROFILE", "prod")
        has, source = auth_probe.provider_has_credentials("aws")
        assert has is True
        assert isinstance(source, str) and source
