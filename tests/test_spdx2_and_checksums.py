"""SPDX 2.2/2.3 emitter and per-component checksum integrity surfacing."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

from agent_bom import checksums as c
from agent_bom.models import (
    Agent,
    AgentStatus,
    AgentType,
    AIBOMReport,
    MCPServer,
    Package,
    Severity,
    TransportType,
    Vulnerability,
)
from agent_bom.output import to_cyclonedx, to_spdx, to_spdx2, to_spdx2_tagvalue
from agent_bom.parsers.node_parsers import parse_npm_packages


def _sri_for(data: bytes, alg: str = "sha512") -> tuple[str, str]:
    """Return (sri_string, expected_hex) for ``data`` under ``alg``."""
    digest = hashlib.new(alg, data).digest()
    return f"{alg}-{base64.b64encode(digest).decode()}", digest.hex()


def _report_with_checksummed_pkg() -> tuple[AIBOMReport, str]:
    sri, expected_hex = _sri_for(b"left-pad payload")
    pkg = Package(
        name="left-pad",
        version="1.3.0",
        ecosystem="npm",
        purl="pkg:npm/left-pad@1.3.0",
        license="MIT",
        checksums=c.parse_sri(sri),
    )
    pkg.vulnerabilities.append(
        Vulnerability(id="CVE-2099-0001", severity=Severity.HIGH, summary="x", cvss_score=7.5, fixed_version="1.3.1")
    )
    server = MCPServer(name="srv", command="npx", args=["srv"], transport=TransportType.STDIO, packages=[pkg])
    agent = Agent(
        name="claude",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/x.json",
        mcp_servers=[server],
        status=AgentStatus.CONFIGURED,
    )
    report = AIBOMReport(
        agents=[agent],
        blast_radii=[],
        generated_at=datetime(2026, 1, 1, 12, 0, 0),
        tool_version="0.90.1",
    )
    return report, expected_hex


# ── checksum normalization helpers ────────────────────────────────────────────


def test_parse_sri_decodes_base64_to_hex():
    sri, expected = _sri_for(b"hello", "sha512")
    assert c.parse_sri(sri) == {"SHA-512": expected}


def test_parse_sri_rejects_malformed_tokens():
    assert c.parse_sri("sha512-not valid base64!!") == {}
    assert c.parse_sri("") == {}
    assert c.parse_sri("md5-AAAA") == {}  # md5 not a recognized SRI prefix


def test_add_checksum_rejects_unknown_alg_and_bad_hex():
    out: dict[str, str] = {}
    c.add_checksum(out, "bogus", "deadbeef")
    c.add_checksum(out, "sha256", "nothex!!")
    c.add_checksum(out, "sha256", "abcd")  # wrong length for sha256
    assert out == {}
    c.add_checksum(out, "sha256", "a" * 64)
    assert out == {"SHA-256": "a" * 64}


# ── SPDX 2.x JSON shape ───────────────────────────────────────────────────────


def test_spdx2_json_has_required_document_fields():
    report, _ = _report_with_checksummed_pkg()
    doc = to_spdx2(report, version="2.3")

    # Required SPDX 2.x document-level fields.
    for field in ("spdxVersion", "dataLicense", "SPDXID", "name", "documentNamespace", "creationInfo"):
        assert field in doc, f"missing required field {field}"
    assert doc["spdxVersion"] == "SPDX-2.3"
    assert doc["dataLicense"] == "CC0-1.0"
    assert doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["creationInfo"]["created"].endswith("Z")
    assert any(creator.startswith("Tool: agent-bom-") for creator in doc["creationInfo"]["creators"])

    # Every package carries the SPDX 2.x mandatory fields.
    assert doc["packages"], "expected at least one package"
    for pkg in doc["packages"]:
        assert pkg["SPDXID"].startswith("SPDXRef-")
        assert "name" in pkg
        assert "downloadLocation" in pkg

    # Document must DESCRIBE its top-level elements.
    assert doc["documentDescribes"]
    assert any(
        r["spdxElementId"] == "SPDXRef-DOCUMENT" and r["relationshipType"] == "DESCRIBES"
        for r in doc["relationships"]
    )

    # Round-trips through JSON.
    assert json.loads(json.dumps(doc)) == doc


def test_spdx2_version_selectable_and_validated():
    report, _ = _report_with_checksummed_pkg()
    assert to_spdx2(report, version="2.2")["spdxVersion"] == "SPDX-2.2"
    with pytest.raises(ValueError):
        to_spdx2(report, version="3.0")


def test_spdx2_surfaces_component_checksums():
    report, expected_hex = _report_with_checksummed_pkg()
    doc = to_spdx2(report, version="2.3")
    libs = [p for p in doc["packages"] if p.get("primaryPackagePurpose") == "LIBRARY"]
    assert libs, "expected a library package"
    checksums = libs[0]["checksums"]
    assert {"algorithm": "SHA512", "checksumValue": expected_hex} in checksums


def test_spdx2_tagvalue_emits_checksum_and_relationships():
    report, expected_hex = _report_with_checksummed_pkg()
    text = to_spdx2_tagvalue(report, version="2.3")
    assert "SPDXVersion: SPDX-2.3" in text
    assert f"PackageChecksum: SHA512: {expected_hex}" in text
    assert "Relationship: SPDXRef-DOCUMENT DESCRIBES" in text


# ── checksums surfaced in 3.0 and CycloneDX too ───────────────────────────────


def test_spdx3_surfaces_verified_using_checksum():
    report, expected_hex = _report_with_checksummed_pkg()
    doc = to_spdx(report)
    pkg_elements = [e for e in doc["elements"] if e.get("software_primaryPurpose") == "library"]
    assert pkg_elements
    verified = pkg_elements[0]["verifiedUsing"]
    assert {"type": "Hash", "algorithm": "sha512", "hashValue": expected_hex} in verified


def test_cyclonedx_surfaces_component_hashes():
    report, expected_hex = _report_with_checksummed_pkg()
    cdx = to_cyclonedx(report)
    libs = [comp for comp in cdx["components"] if comp.get("type") == "library"]
    assert libs
    assert {"alg": "SHA-512", "content": expected_hex} in libs[0]["hashes"]


# ── lockfile integrity capture ────────────────────────────────────────────────


def test_npm_package_lock_populates_checksums(tmp_path: Path):
    sri, expected_hex = _sri_for(b"lodash artifact")
    lock = {
        "name": "app",
        "lockfileVersion": 3,
        "packages": {
            "node_modules/lodash": {"version": "4.17.21", "integrity": sri},
        },
    }
    (tmp_path / "package-lock.json").write_text(json.dumps(lock))
    (tmp_path / "package.json").write_text(json.dumps({"dependencies": {"lodash": "^4.17.21"}}))

    packages = parse_npm_packages(tmp_path)
    lodash = next(p for p in packages if p.name == "lodash")
    assert lodash.checksums == {"SHA-512": expected_hex}
