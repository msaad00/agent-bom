"""Tests for the advisory-remediation foundation (src/agent_bom/remediation.py).

Covers: structured fix + required_privilege (+ artifact) for a CIS finding,
advisory flags, no I/O, degrade-to-recommendation, determinism, and Finding
model round-trip back-compat with and without the field.
"""

from __future__ import annotations

import builtins
import socket

import pytest

from agent_bom.finding import (
    Asset,
    Finding,
    FindingSource,
    FindingType,
    cloud_cis_check_to_finding,
)
from agent_bom.remediation import (
    Remediation,
    RemediationArtifact,
    RemediationFix,
    RequiredPrivilege,
    build_remediation,
)


def _cis_finding() -> Finding:
    """A CIS finding mirroring the AWS 2.1.1 (S3 public access) override."""
    return cloud_cis_check_to_finding(
        {
            "check_id": "2.1.1",
            "title": "Ensure S3 Block Public Access is enabled",
            "severity": "high",
            "evidence": "Bucket allows public access",
            "recommendation": "Enable Block Public Access on the bucket.",
            "cis_section": "2 - Storage",
            "resource_ids": ["my-bucket"],
        },
        provider="aws",
    )


# ---------------------------------------------------------------------------
# fix + required_privilege + artifact for a CIS finding
# ---------------------------------------------------------------------------


def test_build_remediation_cis_returns_fix_privilege_and_artifact() -> None:
    finding = _cis_finding()
    rem = build_remediation(finding)

    assert isinstance(rem, Remediation)
    assert isinstance(rem.fix, RemediationFix)
    assert isinstance(rem.required_privilege, RequiredPrivilege)
    assert isinstance(rem.artifact, RemediationArtifact)

    # fix carries the exact action from the CIS catalog override
    assert rem.fix.cli is not None
    assert "put-public-access-block" in rem.fix.cli
    assert rem.fix.console
    assert rem.fix.summary

    # required_privilege names the least-privilege action to APPLY, not request
    assert rem.required_privilege.actions == ["s3:PutBucketPublicAccessBlock"]
    assert "apply" in rem.required_privilege.description.lower()
    assert "read-only" in rem.required_privilege.scope_note.lower()

    # artifact is a generated runbook (text only)
    assert rem.artifact.kind == "runbook"
    assert "put-public-access-block" in rem.artifact.content
    assert "s3:PutBucketPublicAccessBlock" in rem.artifact.content


def test_advisory_flags_always_set() -> None:
    rem = build_remediation(_cis_finding())
    assert rem.applied is False
    assert rem.auto_remediation is False


def test_cis_finding_populates_remediation_field() -> None:
    finding = _cis_finding()
    assert finding.remediation is not None
    assert finding.remediation.applied is False
    assert finding.remediation.required_privilege.actions


# ---------------------------------------------------------------------------
# Degrade-to-recommendation
# ---------------------------------------------------------------------------


def test_non_cis_finding_degrades_to_recommendation() -> None:
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="torch", asset_type="package", identifier="pkg:pypi/torch@2.3.0"),
        severity="HIGH",
        title="CVE-2024-1: torch",
        remediation_guidance="Upgrade torch to 2.4.0.",
    )
    rem = build_remediation(finding)
    # guidance is never empty
    assert rem.fix.summary == "Upgrade torch to 2.4.0."
    assert rem.required_privilege.description
    assert rem.artifact is None
    assert rem.applied is False
    assert rem.auto_remediation is False


def test_degraded_recommendation_never_empty_without_guidance() -> None:
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="lib", asset_type="package", identifier="pkg:pypi/lib@1.0"),
        severity="MEDIUM",
        title="Some finding",
        remediation_guidance=None,
    )
    rem = build_remediation(finding)
    assert rem.fix.summary  # non-empty fallback guidance


# ---------------------------------------------------------------------------
# Deterministic
# ---------------------------------------------------------------------------


def test_build_remediation_is_deterministic() -> None:
    a = build_remediation(_cis_finding())
    b = build_remediation(_cis_finding())
    assert a.to_dict() == b.to_dict()


# ---------------------------------------------------------------------------
# No I/O — read-only forever
# ---------------------------------------------------------------------------


def test_build_remediation_performs_no_io(monkeypatch: pytest.MonkeyPatch) -> None:
    """Assert build_remediation opens no files and no sockets."""

    def _no_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("remediation must not perform filesystem I/O")

    def _no_socket(*args: object, **kwargs: object) -> None:
        raise AssertionError("remediation must not perform network I/O")

    monkeypatch.setattr(builtins, "open", _no_open)
    monkeypatch.setattr(socket, "socket", _no_socket)

    finding = _cis_finding()
    rem = build_remediation(finding)
    # touch the artifact text to make sure nothing lazily writes
    assert rem.artifact is not None
    assert rem.artifact.content


# ---------------------------------------------------------------------------
# Finding model round-trip back-compat
# ---------------------------------------------------------------------------


def test_finding_to_dict_omits_remediation_when_absent() -> None:
    finding = Finding(
        finding_type=FindingType.CVE,
        source=FindingSource.SBOM,
        asset=Asset(name="pkg", asset_type="package", identifier="pkg:pypi/pkg@1.0"),
        severity="LOW",
        title="x",
    )
    assert finding.remediation is None
    payload = finding.to_dict()
    # Back-compat: no remediation key when the field is unset.
    assert "remediation" not in payload
    # Existing fields untouched.
    assert payload["remediation_guidance"] is None
    assert payload["finding_type"] == "CVE"


def test_finding_to_dict_includes_remediation_when_present() -> None:
    finding = _cis_finding()
    payload = finding.to_dict()
    assert "remediation" in payload
    rem = payload["remediation"]
    assert rem["applied"] is False
    assert rem["auto_remediation"] is False
    assert rem["fix"]["cli"]
    assert rem["required_privilege"]["actions"] == ["s3:PutBucketPublicAccessBlock"]
    assert rem["artifact"]["kind"] == "runbook"


def test_remediation_to_dict_round_trip_shape() -> None:
    rem = build_remediation(_cis_finding())
    d = rem.to_dict()
    assert set(d) == {
        "schema_version",
        "fix",
        "required_privilege",
        "artifact",
        "effort",
        "priority",
        "guardrails",
        "applied",
        "auto_remediation",
    }
