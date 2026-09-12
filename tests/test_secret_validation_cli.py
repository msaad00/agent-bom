"""CLI consent, offline exclusion and unchanged security verdicts."""

import json

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.scanners.credential_validation import CredentialValidator


def test_offline_rejects_validation_before_scanning(tmp_path, monkeypatch):
    from agent_bom import secret_scanner

    def forbidden(*args, **kwargs):
        pytest.fail("Conflicting options must fail before scanning")

    monkeypatch.setattr(secret_scanner, "scan_secrets", forbidden)
    result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--offline", "--validate-credentials"])
    assert result.exit_code == 2
    assert "cannot be combined" in result.output


@pytest.mark.parametrize("format", ["json", "console"])
def test_explicit_cli_validation_surfaces_verdict_without_changing_exit(tmp_path, monkeypatch, format):
    value = "ghp_" + "Ab9Xz2Kp7Qr4Mn8Tv6Ws1Yc5Hd3Ef0Gj9La2B"
    (tmp_path / "settings.env").write_text(f'TOKEN="{value}"\n')
    monkeypatch.setattr(CredentialValidator, "validate", lambda self, kind, secret: "invalid")
    result = CliRunner().invoke(main, ["secrets", str(tmp_path), "--validate-credentials", "--format", format])
    assert result.exit_code == 1, result.output
    assert value not in result.output
    if format == "json":
        assert json.loads(result.stdout)["findings"][0]["validation_status"] == "invalid"
    else:
        assert "validation: invalid" in result.stdout
