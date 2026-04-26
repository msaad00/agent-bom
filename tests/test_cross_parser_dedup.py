"""Cross-parser, cross-ecosystem package dedup tests.

#1815 explicitly asks for proof that equivalent packages do not split across
parsers and import paths. This file pins the contract:

- two parsers emitting the same PyPI package with different name casing /
  separator style collapse to one graph node
- a parser emitting an explicit purl plus another parser emitting raw
  name/version collapse to one graph node
- npm packages emitted by multiple JS-ecosystem parsers (npm/yarn/pnpm-style
  paths all label as ``npm`` in agent-bom) collapse to one graph node
- image OS package parsers (deb, apk, rpm) live in their own ecosystems and
  do NOT collide with each other or with PyPI/npm

The tests intentionally exercise ``build_unified_graph_from_report`` end to
end so any future ecosystem-alias regression in
``src/agent_bom/package_utils.py`` or in the graph builder shows up here.
"""

from __future__ import annotations

from agent_bom.graph import EntityType
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.package_utils import canonical_package_key, normalize_package_name


def _agent(name: str, server_name: str, packages: list[dict]) -> dict:
    return {
        "name": name,
        "type": "claude-desktop",
        "status": "configured",
        "config_path": f"/cfg/{name}.json",
        "mcp_servers": [
            {
                "name": server_name,
                "command": "npx",
                "transport": "stdio",
                "surface": "mcp-server",
                "packages": packages,
            }
        ],
    }


def _report(*agents: dict) -> dict:
    return {"scan_id": "dedup-001", "agents": list(agents), "blast_radius": []}


def test_pypi_parsers_with_different_name_casing_collapse_to_one_node() -> None:
    # PyPI normalization (PEP 503) flattens case and `-/_/.` to `-`.
    # Two parsers emitting "Requests" and "requests" must dedupe.
    pkg_a = {"name": "Requests", "version": "2.31.0", "ecosystem": "pypi", "vulnerabilities": []}
    pkg_b = {"name": "requests", "version": "2.31.0", "ecosystem": "pypi", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-a", "srv-a", [pkg_a]),
            _agent("agent-b", "srv-b", [pkg_b]),
        )
    )
    pkg_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if "requests" in n.id.lower()]
    assert len(pkg_nodes) == 1, [n.id for n in pkg_nodes]


def test_pypi_separator_variations_collapse_to_one_node() -> None:
    # Same PEP 503 rule: `urllib_3`, `urllib.3`, `urllib-3` are the same name.
    pkg_a = {"name": "Urllib_3", "version": "2.0.4", "ecosystem": "pypi", "vulnerabilities": []}
    pkg_b = {"name": "urllib.3", "version": "2.0.4", "ecosystem": "pypi", "vulnerabilities": []}
    pkg_c = {"name": "urllib-3", "version": "2.0.4", "ecosystem": "pypi", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-a", "srv-a", [pkg_a, pkg_b, pkg_c]),
        )
    )
    pkg_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if "urllib-3" in n.id]
    assert len(pkg_nodes) == 1, [n.id for n in pkg_nodes]


def test_explicit_purl_and_raw_pypi_collapse_to_one_node() -> None:
    # One parser carries a full purl, another only carries name/version. The
    # canonical identity must be the same so the package surfaces once.
    purl = "pkg:pypi/[email protected]"
    pkg_purl = {"name": "PyYAML", "version": "6.0.1", "ecosystem": "pypi", "purl": purl, "vulnerabilities": []}
    pkg_raw = {"name": "pyyaml", "version": "6.0.1", "ecosystem": "pypi", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-a", "srv-a", [pkg_purl]),
            _agent("agent-b", "srv-b", [pkg_raw]),
        )
    )
    pkg_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if "pyyaml" in n.id]
    assert len(pkg_nodes) == 1, [n.id for n in pkg_nodes]


def test_npm_parsers_collapse_to_one_node() -> None:
    # agent-bom labels npm/yarn/pnpm parsers as the ``npm`` ecosystem so they
    # share an OSV namespace. Same name + version must dedupe to one node.
    pkg_a = {"name": "Express", "version": "4.18.2", "ecosystem": "npm", "vulnerabilities": []}
    pkg_b = {"name": "express", "version": "4.18.2", "ecosystem": "npm", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-a", "srv-a", [pkg_a]),
            _agent("agent-b", "srv-b", [pkg_b]),
        )
    )
    pkg_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if "express" in n.id]
    assert len(pkg_nodes) == 1, [n.id for n in pkg_nodes]


def test_image_os_packages_stay_in_their_own_ecosystems() -> None:
    # deb, apk, rpm are real distinct OSV namespaces. A debian openssl row and
    # an alpine openssl row must NOT collapse: they are different artifacts
    # with different vulnerability contracts even when the binary name matches.
    pkg_deb = {"name": "openssl", "version": "3.0.11-1~deb12u1", "ecosystem": "deb", "vulnerabilities": []}
    pkg_apk = {"name": "openssl", "version": "3.1.4-r1", "ecosystem": "apk", "vulnerabilities": []}
    pkg_rpm = {"name": "openssl", "version": "3.0.7-25.el9_2", "ecosystem": "rpm", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-deb", "srv-deb", [pkg_deb]),
            _agent("agent-apk", "srv-apk", [pkg_apk]),
            _agent("agent-rpm", "srv-rpm", [pkg_rpm]),
        )
    )
    openssl_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if normalize_package_name("openssl") in n.id]
    ecosystems = sorted({n.id.split(":", 2)[1] for n in openssl_nodes})
    assert ecosystems == ["apk", "deb", "rpm"], ecosystems


def test_pypi_and_conda_packages_do_not_collide() -> None:
    # Conda packages can share a name with a PyPI distribution but are
    # different artifacts (conda-forge is its own OSV namespace). The graph
    # must keep them separate so vulnerability evidence does not cross paths.
    pkg_pypi = {"name": "numpy", "version": "1.26.0", "ecosystem": "pypi", "vulnerabilities": []}
    pkg_conda = {"name": "numpy", "version": "1.26.0", "ecosystem": "conda", "vulnerabilities": []}
    g = build_unified_graph_from_report(
        _report(
            _agent("agent-pypi", "srv-pypi", [pkg_pypi]),
            _agent("agent-conda", "srv-conda", [pkg_conda]),
        )
    )
    numpy_nodes = [n for n in g.nodes_by_type(EntityType.PACKAGE) if "numpy" in n.id]
    ecosystems = sorted({n.id.split(":", 2)[1] for n in numpy_nodes})
    assert ecosystems == ["conda", "pypi"], ecosystems


def test_canonical_package_key_collapses_golang_alias() -> None:
    # _PURL_TYPE_ALIASES collapses `golang` -> `go` so two parsers naming the
    # same Go module under different ecosystem labels share one identity.
    go_form = canonical_package_key("logrus", "1.9.3", "go")
    golang_form = canonical_package_key("logrus", "1.9.3", "golang")
    assert go_form == golang_form == "go:logrus@1.9.3"
