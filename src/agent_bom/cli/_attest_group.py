"""CLI: sign and verify generated SBOM output.

``agent-bom attest sign <sbom>``   — emit a detached signature + in-toto attestation
``agent-bom attest verify <sbom>`` — verify the SBOM against its attestation
"""

from __future__ import annotations

import json
from pathlib import Path

import click

from agent_bom.sbom_attestation import (
    AttestationSigningError,
    AttestationTrustError,
    AttestationTrustPolicy,
    sign_sbom_file,
    verify_sbom_attestation,
)


@click.group("attest")
def attest_group() -> None:
    """Sign and verify generated SBOM output (digest + in-toto attestation)."""


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
def sign_cmd(sbom_path: str, sig_out: str | None, att_out: str | None, as_json: bool) -> None:
    """Sign a generated SBOM file: SHA-256 digest + signed in-toto attestation."""
    try:
        result = sign_sbom_file(sbom_path, signature_path=sig_out, attestation_path=att_out)
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
@click.option("--json", "as_json", is_flag=True, help="Emit machine-readable JSON.")
def verify_cmd(
    sbom_path: str,
    att_path: str | None,
    sig_path: str | None,
    public_key_paths: tuple[str, ...],
    as_json: bool,
) -> None:
    """Verify a generated SBOM against its in-toto attestation and detached signature."""
    trust_policy = None
    if public_key_paths:
        try:
            pems: list[str] = []
            for raw_path in public_key_paths:
                path = Path(raw_path)
                if path.stat().st_size > 64 * 1024:
                    raise AttestationTrustError("trusted_public_key_file_too_large")
                pems.append(path.read_text(encoding="utf-8"))
            trust_policy = AttestationTrustPolicy.from_public_key_pems(pems)
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
