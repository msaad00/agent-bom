"""CLI surface for MCP scan attestations (sign + verify)."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from agent_bom.cli._attest_group import attest_group


def _write_keypair(tmp_path: Path) -> tuple[Path, Path]:
    key = Ed25519PrivateKey.generate()
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_path = tmp_path / "mcp-scan.pem"
    public_path = tmp_path / "mcp-scan.pub.pem"
    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)
    return private_path, public_path


def _scan_report() -> dict:
    return {
        "scan_id": "scan-cli-0001",
        "generated_at": "2026-07-21T00:00:00Z",
        "agents": [
            {
                "name": "demo-agent",
                "mcp_servers": [
                    {
                        "name": "filesystem-server",
                        "stable_id": "e12d0e98-312b-5ade-843f-bc7c90b4a565",
                        "canonical_id": "e12d0e98-312b-5ade-843f-bc7c90b4a565",
                        "fingerprint": "e1c98e6d-e7a2-54eb-b0d1-61a9b93ab13f",
                        "command": "npx @modelcontextprotocol/server-filesystem /",
                        "args": [],
                        "transport": "stdio",
                        "security_blocked": False,
                        "packages": [{"name": "node-fetch", "version": "2.6.1", "ecosystem": "npm"}],
                    }
                ],
            }
        ],
        "findings": [
            {
                "id": "finding-1",
                "severity": "high",
                "finding_category": "vulnerability",
                "vulnerability_id": "CVE-2022-0235",
                "title": "CVE-2022-0235: node-fetch@2.6.1",
                "affected_servers": ["filesystem-server"],
            }
        ],
    }


def test_attest_mcp_sign_verify_round_trip(tmp_path: Path, monkeypatch) -> None:
    private_path, public_path = _write_keypair(tmp_path)
    monkeypatch.setenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM_FILE", str(private_path))
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(_scan_report()), encoding="utf-8")
    out_path = tmp_path / "server.mcp-attestation.intoto.json"

    runner = CliRunner()
    sign = runner.invoke(
        attest_group,
        [
            "mcp",
            "sign",
            str(scan_path),
            "--server",
            "filesystem-server",
            "--tenant-id",
            "tenant-a",
            "--out",
            str(out_path),
            "--json",
        ],
    )
    assert sign.exit_code == 0, sign.output
    signed = json.loads(sign.output)
    assert signed["signed"] is True
    assert signed["verdict"] in {"WARN", "FAIL", "PASS", "BLOCK"}
    assert out_path.is_file()

    verify = runner.invoke(
        attest_group,
        [
            "mcp",
            "verify",
            str(out_path),
            "--tenant-id",
            "tenant-a",
            "--public-key",
            str(public_path),
            "--json",
        ],
    )
    assert verify.exit_code == 0, verify.output
    receipt = json.loads(verify.output)
    assert receipt["verified"] is True
    assert receipt["trust_state"] == "verified"
    assert receipt["catalog_id"] == "e12d0e98-312b-5ade-843f-bc7c90b4a565"


def test_attest_mcp_sign_fails_closed_without_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM", raising=False)
    monkeypatch.delenv("AGENT_BOM_MCP_SCAN_ED25519_PRIVATE_KEY_PEM_FILE", raising=False)
    scan_path = tmp_path / "scan.json"
    scan_path.write_text(json.dumps(_scan_report()), encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        attest_group,
        ["mcp", "sign", str(scan_path), "--server", "filesystem-server", "--tenant-id", "tenant-a", "--json"],
    )
    assert result.exit_code == 1
    payload = json.loads(result.output)
    assert payload["signed"] is False
    assert payload["reason"] == "mcp_signing_key_required"
