"""Credential-bearing files must enter the secret scanner candidate set."""

from pathlib import Path

import pytest

from agent_bom.secret_scanner import scan_secrets

# Real-shaped only after Python joins the fragments, so the regression tests
# credential detection without committing a token-shaped literal.
LEAKED_KEY = "AKIA" + "IOSFODNN7" + "EXAMPLE"

SENSITIVE_FILENAMES = (
    "server.pem",
    "client.pem",
    "signing.pem",
    "tls.pem",
    "private.pem",
    "server.key",
    "client.key",
    "signing.key",
    "tls.key",
    "private.key",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    "identity",
    "private_key",
    "signing_key",
    "credentials",
    "secrets",
    "token",
)


@pytest.mark.parametrize("filename", SENSITIVE_FILENAMES)
def test_sensitive_file_is_scanned_for_credential_material(tmp_path: Path, filename: str) -> None:
    target = tmp_path / filename
    target.write_text(f"AWS_ACCESS_KEY_ID={LEAKED_KEY}\n", encoding="utf-8")

    result = scan_secrets(tmp_path)

    assert result.files_scanned == 1
    assert result.to_dict()["complete"] is True
    assert any(finding.file_path == filename and finding.secret_type == "AWS Access Key" for finding in result.findings)
