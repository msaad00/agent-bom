"""Tests for SBOM ingestion — multi-hop dependency graph and CycloneDX vulnerabilities[] ingest (Issue #546)."""

from agent_bom.sbom import parse_cyclonedx


def _make_cyclonedx(components, dependencies=None, vulnerabilities=None):
    """Build a minimal CycloneDX JSON document for testing."""
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "metadata": {
            "component": {
                "bom-ref": "root",
                "name": "my-app",
                "version": "1.0.0",
            }
        },
        "components": components,
    }
    if dependencies is not None:
        doc["dependencies"] = dependencies
    if vulnerabilities is not None:
        doc["vulnerabilities"] = vulnerabilities
    return doc


# ─── Multi-hop dependency depth tests ─────────────────────────────────────────


def test_direct_dependency_depth_zero():
    """A package directly depended on by root should have dependency_depth=0 by default."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
        ],
        dependencies=[
            {"ref": "root", "dependsOn": ["pkg-a"]},
            {"ref": "pkg-a", "dependsOn": []},
        ],
    )
    packages = parse_cyclonedx(doc)
    pkg_a = next(p for p in packages if p.name == "pkg-a")
    assert pkg_a.is_direct is True


def test_multihop_depth_tracking():
    """A→B→C chain: C should have dependency_depth=2."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
            {"bom-ref": "pkg-b", "name": "pkg-b", "version": "2.0", "purl": "pkg:pypi/pkg-b@2.0"},
            {"bom-ref": "pkg-c", "name": "pkg-c", "version": "3.0", "purl": "pkg:pypi/pkg-c@3.0"},
        ],
        dependencies=[
            {"ref": "root", "dependsOn": ["pkg-a"]},
            {"ref": "pkg-a", "dependsOn": ["pkg-b"]},
            {"ref": "pkg-b", "dependsOn": ["pkg-c"]},
            {"ref": "pkg-c", "dependsOn": []},
        ],
    )
    packages = parse_cyclonedx(doc)
    by_name = {p.name: p for p in packages}

    # pkg-c is 2 hops from root (root→A→B→C)
    assert by_name["pkg-c"].dependency_depth == 2


def test_multihop_transitive_not_direct():
    """Packages 2+ hops from root should not be marked direct."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
            {"bom-ref": "pkg-b", "name": "pkg-b", "version": "2.0", "purl": "pkg:pypi/pkg-b@2.0"},
            {"bom-ref": "pkg-c", "name": "pkg-c", "version": "3.0", "purl": "pkg:pypi/pkg-c@3.0"},
        ],
        dependencies=[
            {"ref": "root", "dependsOn": ["pkg-a"]},
            {"ref": "pkg-a", "dependsOn": ["pkg-b"]},
            {"ref": "pkg-b", "dependsOn": ["pkg-c"]},
            {"ref": "pkg-c", "dependsOn": []},
        ],
    )
    packages = parse_cyclonedx(doc)
    by_name = {p.name: p for p in packages}

    # pkg-b and pkg-c should not be marked as direct
    assert by_name["pkg-b"].is_direct is False
    assert by_name["pkg-c"].is_direct is False


def test_cycle_in_deps_no_infinite_loop():
    """Cyclic dependency graph should not cause infinite recursion."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
            {"bom-ref": "pkg-b", "name": "pkg-b", "version": "2.0", "purl": "pkg:pypi/pkg-b@2.0"},
        ],
        dependencies=[
            {"ref": "root", "dependsOn": ["pkg-a"]},
            {"ref": "pkg-a", "dependsOn": ["pkg-b"]},
            {"ref": "pkg-b", "dependsOn": ["pkg-a"]},  # cycle
        ],
    )
    # Should not raise RecursionError
    packages = parse_cyclonedx(doc)
    assert len(packages) == 2


# ─── CycloneDX vulnerabilities[] ingest tests ─────────────────────────────────


def test_cyclonedx_vulnerabilities_ingested():
    """CycloneDX vulnerabilities[] array should be ingested and attached to packages."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
        ],
        vulnerabilities=[
            {
                "id": "CVE-2024-12345",
                "description": "A critical vulnerability",
                "ratings": [{"severity": "critical", "score": 9.8}],
                "affects": [{"ref": "pkg-a"}],
            }
        ],
    )
    packages = parse_cyclonedx(doc)
    pkg_a = next(p for p in packages if p.name == "pkg-a")
    assert len(pkg_a.vulnerabilities) == 1
    assert pkg_a.vulnerabilities[0].id == "CVE-2024-12345"


def test_cyclonedx_vuln_severity_mapped():
    """Vulnerability severity from CycloneDX ratings should be mapped to Severity enum."""
    from agent_bom.models import Severity

    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-x", "name": "pkg-x", "version": "2.0", "purl": "pkg:pypi/pkg-x@2.0"},
        ],
        vulnerabilities=[
            {
                "id": "CVE-2024-99999",
                "description": "A high severity issue",
                "ratings": [{"severity": "high", "score": 7.5}],
                "affects": [{"ref": "pkg-x"}],
            }
        ],
    )
    packages = parse_cyclonedx(doc)
    pkg_x = next(p for p in packages if p.name == "pkg-x")
    assert pkg_x.vulnerabilities[0].severity == Severity.HIGH
    assert pkg_x.vulnerabilities[0].cvss_score == 7.5


def test_cyclonedx_vuln_unaffected_package_skipped():
    """Vulnerabilities with affects[] not matching any package should not be attached."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
        ],
        vulnerabilities=[
            {
                "id": "CVE-2024-00000",
                "description": "Unrelated",
                "ratings": [{"severity": "medium"}],
                "affects": [{"ref": "pkg-does-not-exist"}],
            }
        ],
    )
    packages = parse_cyclonedx(doc)
    pkg_a = next(p for p in packages if p.name == "pkg-a")
    assert len(pkg_a.vulnerabilities) == 0


def test_cyclonedx_no_vulnerabilities_key():
    """Documents without a vulnerabilities[] key should parse without error."""
    doc = _make_cyclonedx(
        components=[
            {"bom-ref": "pkg-a", "name": "pkg-a", "version": "1.0", "purl": "pkg:pypi/pkg-a@1.0"},
        ],
    )
    packages = parse_cyclonedx(doc)
    assert len(packages) == 1
    assert len(packages[0].vulnerabilities) == 0
