"""CLI: sign and verify generated SBOM output and MCP scan attestations.

``agent-bom attest sign <sbom>``   — emit a detached signature + in-toto attestation
``agent-bom attest verify <sbom>`` — verify the SBOM against its attestation
``agent-bom attest mcp sign <scan.json>`` — sign a per-instance MCP scan attestation
``agent-bom attest mcp verify <attestation>`` — verify an MCP scan attestation
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from agent_bom.mcp_scan_attestation import (
    Ed25519MCPScanSigner,
    MCPScanTrustPolicy,
    accept_mcp_scan_attestation,
    evidence_from_scan_report,
    mcp_catalog_attestation_receipt,
    sign_mcp_scan_attestation,
    verify_mcp_scan_attestation,
)
from agent_bom.sbom_attestation import (
    AttestationSigningError,
    AttestationTrustError,
    AttestationTrustPolicy,
    MemoryAttestationReplayStore,
    SQLiteAttestationReplayStore,
    sign_sbom_file,
    verify_sbom_attestation,
)


@click.group("attest")
def attest_group() -> None:
    """Sign and verify SBOM and MCP scan attestations (digest + in-toto / DSSE)."""


@attest_group.command("sign")
@click.argument("sbom_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--sig-out", "sig_out", type=click.Path(dir_okay=False), default=None, help="Detached signature path (default: <sbom>.sig).")
@click.option(
    "--attestation-out",
    "att_out",
    type=click.Path(dir_okay=False),
    default=None,
    help="Attestation path (default: <sbom>.intoto.json).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
@click.option("--tenant-id", required=True, help="Tenant bound into the signed attestation.")
@click.option("--ttl-seconds", type=click.IntRange(1, 2_592_000), default=900, show_default=True)
def sign_cmd(
    sbom_path: str,
    sig_out: str | None,
    att_out: str | None,
    as_json: bool,
    tenant_id: str,
    ttl_seconds: int,
) -> None:
    """Sign a generated SBOM file: SHA-256 digest + signed in-toto attestation."""
    try:
        result = sign_sbom_file(
            sbom_path,
            signature_path=sig_out,
            attestation_path=att_out,
            tenant_id=tenant_id,
            ttl_seconds=ttl_seconds,
        )
    except AttestationSigningError as exc:
        reason = str(exc)
        if as_json:
            click.echo(json.dumps({"sbom": sbom_path, "signed": False, "reason": reason}, indent=2))
        else:
            click.echo(f"FAILED: {sbom_path}\n  reason: {reason}")
        raise SystemExit(1) from None
    if as_json:
        click.echo(
            json.dumps(
                {
                    "sbom": result.sbom_path,
                    "sha256": result.sha256,
                    "algorithm": result.algorithm,
                    "cryptographic": result.cryptographic,
                    "key_id": result.key_id,
                    "signature": result.signature_path,
                    "attestation": result.attestation_path,
                },
                indent=2,
            )
        )
        return
    click.echo(f"Signed SBOM:   {result.sbom_path}")
    click.echo(f"  sha256:      {result.sha256}")
    click.echo(f"  algorithm:   {result.algorithm}")
    if result.key_id:
        click.echo(f"  key_id:      {result.key_id}")
    click.echo(f"  signature:   {result.signature_path}")
    click.echo(f"  attestation: {result.attestation_path}")


@attest_group.command("verify")
@click.argument("sbom_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--attestation",
    "att_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Attestation path (default: <sbom>.intoto.json).",
)
@click.option(
    "--signature",
    "sig_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Detached signature path (default: <sbom>.sig).",
)
@click.option(
    "--public-key",
    "public_key_paths",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    multiple=True,
    help="Trusted Ed25519 public-key PEM file. Repeat for key rotation; embedded envelope keys are never trusted.",
)
@click.option("--tenant-id", required=True, help="Expected signed tenant boundary.")
@click.option("--max-age-seconds", type=click.IntRange(1, 2_592_000), default=3600, show_default=True)
@click.option("--clock-skew-seconds", type=click.IntRange(0, 300), default=60, show_default=True)
@click.option(
    "--replay-cache",
    type=click.Path(dir_okay=False),
    default=None,
    help="SQLite replay cache shared across verifier processes. Without it, replay state is process-local.",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def verify_cmd(
    sbom_path: str,
    att_path: str | None,
    sig_path: str | None,
    public_key_paths: tuple[str, ...],
    tenant_id: str,
    max_age_seconds: int,
    clock_skew_seconds: int,
    replay_cache: str | None,
    as_json: bool,
) -> None:
    """Verify a generated SBOM against its in-toto attestation and detached signature."""
    trust_policy = None
    replay_store = SQLiteAttestationReplayStore(replay_cache) if replay_cache else MemoryAttestationReplayStore()
    if public_key_paths:
        try:
            pems: list[str] = []
            for raw_path in public_key_paths:
                path = Path(raw_path)
                if path.stat().st_size > 64 * 1024:
                    raise AttestationTrustError("trusted_public_key_file_too_large")
                pems.append(path.read_text(encoding="utf-8"))
            trust_policy = AttestationTrustPolicy.from_public_key_pems(
                pems,
                expected_tenant_id=tenant_id,
                max_age_seconds=max_age_seconds,
                clock_skew_seconds=clock_skew_seconds,
                replay_store=replay_store,
            )
        except (OSError, UnicodeError, AttestationTrustError) as exc:
            reason = str(exc) if isinstance(exc, AttestationTrustError) else "trusted_public_key_unreadable"
            if as_json:
                click.echo(json.dumps({"sbom": sbom_path, "verified": False, "reason": reason}, indent=2))
            else:
                click.echo(f"FAILED: {sbom_path}\n  reason: {reason}")
            raise SystemExit(1) from None
    result = verify_sbom_attestation(
        sbom_path,
        attestation_path=att_path,
        signature_path=sig_path,
        trust_policy=trust_policy,
    )
    if as_json:
        click.echo(
            json.dumps(
                {
                    "sbom": result.sbom_path,
                    "verified": result.verified,
                    "algorithm": result.algorithm,
                    "cryptographic": result.cryptographic,
                    "digest_matches": result.digest_matches,
                    "signature_valid": result.signature_valid,
                    "reason": result.reason,
                    "checks": result.checks,
                    "expected_sha256": result.expected_sha256,
                    "actual_sha256": result.actual_sha256,
                    "format_version": result.format_version,
                    "legacy": result.legacy,
                    "trust_status": result.trust_status,
                    "tenant_id": result.tenant_id,
                    "evidence_id": result.evidence_id,
                    "issued_at": result.issued_at,
                    "expires_at": result.expires_at,
                },
                indent=2,
            )
        )
    else:
        status = "VERIFIED" if result.verified else "FAILED"
        click.echo(f"{status}: {result.sbom_path}")
        click.echo(f"  reason:    {result.reason}")
        click.echo(f"  algorithm: {result.algorithm}")
        for check in result.checks:
            click.echo(f"  check:     {check}")
    if not result.verified:
        raise SystemExit(1)


@attest_group.group("mcp")
def mcp_attest_group() -> None:
    """Sign and verify per-instance MCP server scan attestations."""


@mcp_attest_group.command("sign")
@click.argument("scan_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--server",
    required=True,
    help="MCP server name, stable_id, canonical_id, or registry_id from the scan report.",
)
@click.option("--tenant-id", required=True, help="Tenant bound into the signed attestation.")
@click.option(
    "--verdict",
    type=click.Choice(["PASS", "WARN", "FAIL", "BLOCK", "UNKNOWN"], case_sensitive=False),
    default=None,
    help="Override auto-derived verdict from security_blocked / finding severity.",
)
@click.option("--ttl-seconds", type=click.IntRange(1, 2_592_000), default=86_400, show_default=True)
@click.option(
    "--out",
    "out_path",
    type=click.Path(dir_okay=False),
    default=None,
    help="Attestation path (default: <scan>.mcp-attestation.intoto.json).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def mcp_sign_cmd(
    scan_path: str,
    server: str,
    tenant_id: str,
    verdict: str | None,
    ttl_seconds: int,
    out_path: str | None,
    as_json: bool,
) -> None:
    """Sign a completed scan JSON into a DSSE MCP scan attestation for one server."""
    try:
        report = json.loads(Path(scan_path).read_text(encoding="utf-8"))
        if not isinstance(report, dict):
            raise AttestationSigningError("scan_report_invalid")
        evidence = evidence_from_scan_report(
            report,
            server=server,
            tenant_id=tenant_id,
            verdict=verdict.upper() if verdict else None,
            ttl_seconds=ttl_seconds,
        )
        envelope = sign_mcp_scan_attestation(evidence, signer=Ed25519MCPScanSigner.from_env())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        reason = "scan_report_unreadable"
        if as_json:
            click.echo(json.dumps({"scan": scan_path, "signed": False, "reason": reason}, indent=2))
        else:
            click.echo(f"FAILED: {scan_path}\n  reason: {reason}")
        raise SystemExit(1) from exc
    except AttestationSigningError as exc:
        reason = str(exc)
        if as_json:
            click.echo(json.dumps({"scan": scan_path, "signed": False, "reason": reason}, indent=2))
        else:
            click.echo(f"FAILED: {scan_path}\n  reason: {reason}")
        raise SystemExit(1) from None

    destination = Path(out_path) if out_path else Path(f"{scan_path}.mcp-attestation.intoto.json")
    destination.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if as_json:
        click.echo(
            json.dumps(
                {
                    "scan": scan_path,
                    "signed": True,
                    "server": server,
                    "catalog_id": evidence.catalog_id,
                    "verdict": evidence.verdict,
                    "instance_digest": evidence.instance_digest,
                    "attestation": str(destination),
                    "key_id": envelope["signatures"][0]["keyid"],
                },
                indent=2,
            )
        )
        return
    click.echo(f"Signed MCP scan attestation: {destination}")
    click.echo(f"  server:     {server}")
    click.echo(f"  catalog_id: {evidence.catalog_id}")
    click.echo(f"  verdict:    {evidence.verdict}")
    click.echo(f"  digest:     {evidence.instance_digest}")


@mcp_attest_group.command("verify")
@click.argument("attestation_path", type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option(
    "--public-key",
    "public_key_paths",
    type=click.Path(exists=True, dir_okay=False, readable=True),
    multiple=True,
    required=True,
    help="Trusted Ed25519 public-key PEM file. Repeat for key rotation; embedded envelope keys are never trusted.",
)
@click.option("--tenant-id", required=True, help="Expected signed tenant boundary.")
@click.option("--max-age-seconds", type=click.IntRange(1, 2_592_000), default=86_400, show_default=True)
@click.option("--clock-skew-seconds", type=click.IntRange(0, 300), default=60, show_default=True)
@click.option(
    "--replay-cache",
    type=click.Path(dir_okay=False),
    default=None,
    help="SQLite replay cache used only with --accept.",
)
@click.option(
    "--accept",
    "do_accept",
    is_flag=True,
    help="Verify then consume the attestation once (replay-guarded acceptance).",
)
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def mcp_verify_cmd(
    attestation_path: str,
    public_key_paths: tuple[str, ...],
    tenant_id: str,
    max_age_seconds: int,
    clock_skew_seconds: int,
    replay_cache: str | None,
    do_accept: bool,
    as_json: bool,
) -> None:
    """Verify a DSSE MCP scan attestation against an operator trust policy."""
    try:
        envelope = json.loads(Path(attestation_path).read_text(encoding="utf-8"))
        if not isinstance(envelope, dict):
            raise AttestationTrustError("attestation_invalid")
        pems: list[str] = []
        for raw_path in public_key_paths:
            path = Path(raw_path)
            if path.stat().st_size > 64 * 1024:
                raise AttestationTrustError("trusted_public_key_file_too_large")
            pems.append(path.read_text(encoding="utf-8"))
        trust_policy = MCPScanTrustPolicy.from_public_key_pems(
            pems,
            expected_tenant_id=tenant_id,
            max_age_seconds=max_age_seconds,
            clock_skew_seconds=clock_skew_seconds,
        )
        if do_accept:
            replay_store = SQLiteAttestationReplayStore(replay_cache) if replay_cache else MemoryAttestationReplayStore()
            result = accept_mcp_scan_attestation(envelope, trust_policy=trust_policy, replay_store=replay_store)
        else:
            result = verify_mcp_scan_attestation(envelope, trust_policy=trust_policy)
    except (OSError, UnicodeError, json.JSONDecodeError):
        reason = "attestation_unreadable"
        if as_json:
            click.echo(json.dumps({"attestation": attestation_path, "verified": False, "reason": reason}, indent=2))
        else:
            click.echo(f"FAILED: {attestation_path}\n  reason: {reason}")
        raise SystemExit(1) from None
    except AttestationTrustError as exc:
        reason = str(exc)
        if as_json:
            click.echo(json.dumps({"attestation": attestation_path, "verified": False, "reason": reason}, indent=2))
        else:
            click.echo(f"FAILED: {attestation_path}\n  reason: {reason}")
        raise SystemExit(1) from None

    receipt = mcp_catalog_attestation_receipt(result)
    if as_json:
        click.echo(json.dumps({"attestation": attestation_path, **receipt}, indent=2))
    else:
        status = "VERIFIED" if result.verified else "FAILED"
        click.echo(f"{status}: {attestation_path}")
        click.echo(f"  reason:     {result.reason}")
        click.echo(f"  trust:      {result.trust_state}")
        click.echo(f"  verdict:    {result.verdict}")
        click.echo(f"  catalog_id: {result.catalog_id}")
        for check in result.checks:
            click.echo(f"  check:      {check}")
    if not result.verified:
        raise SystemExit(1)
