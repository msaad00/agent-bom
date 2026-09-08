"""Product entry points share graph terminology and name shipped compliance mappings."""

from pathlib import Path

from agent_bom.output.compliance_narrative import ALL_FRAMEWORK_SLUGS

ROOT = Path(__file__).resolve().parents[1]


def test_product_entrypoints_share_a_graph_definition() -> None:
    definition = (
        "The shared security graph connects packages, workloads, agents, tools, identities, "
        "and data assets through typed relationships with source evidence and explicit completeness."
    )
    for name in ("DOCKER_HUB_README.md", "site-docs/index.md"):
        assert definition in " ".join((ROOT / name).read_text().split())
    readme = (ROOT / "README.md").read_text()
    assert "[Evidence workflow](docs/HOW_IT_WORKS.md)" in readme
    vocabulary = (ROOT / "docs/HOW_IT_WORKS.md").read_text()
    for term in ("`UnifiedGraph`", "`ContextGraph`", "**Mesh**", "**Evidence**", "**Current**", "**Proposed**", "**Difference**"):
        assert term in vocabulary
    assert "A directed relationship records how two entities connect" in vocabulary
    assert "observed, inferred, or modeled" in vocabulary


def test_readme_explains_blast_radius_before_screenshots_without_exploit_claim() -> None:
    readme = (ROOT / "README.md").read_text()
    tour = readme.split("### AppSec and cloud teams", 1)[1].split("### Engineers and GRC", 1)[0]
    assert tour.index("CVE-2023-4863 in pillow@9.0.0") < tour.index("correlation-graph-live.png")
    for marker in ("workload identity", "reachable data asset", "source receipts", "remediation"):
        assert marker in tour
    assert "modeled infrastructure" in readme
    assert "A blocked call does not establish that the underlying package was fixed" in readme
    workflow = " ".join((ROOT / "docs/HOW_IT_WORKS.md").read_text().split())
    assert "a drawn connection alone is not exploit proof" in workflow


def test_readme_grc_links_shipped_narrative_mappings_without_certification_claim() -> None:
    assert {"owasp-llm", "atlas", "eu-ai-act", "nist"} <= set(ALL_FRAMEWORK_SLUGS)
    readme = (ROOT / "README.md").read_text()
    row = next(line for line in readme.splitlines() if line.startswith("| **GRC & audit**"))
    assert "assessment gaps" in row
    assert "docs/GALLERY.md#scan-a-repository-before-shipping" in row
    assert "Control mappings are not audit certification" in readme
    scenario = (ROOT / "docs/GALLERY.md").read_text()
    assert "agent-bom report compliance-narrative scan.json" in scenario
