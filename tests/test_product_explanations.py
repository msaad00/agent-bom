"""Product entry points share graph terminology and name shipped compliance mappings."""

from pathlib import Path

from agent_bom.output.compliance_narrative import ALL_FRAMEWORK_SLUGS

ROOT = Path(__file__).resolve().parents[1]


def test_product_entrypoints_share_a_graph_definition() -> None:
    definition = (
        "The shared security graph connects packages, workloads, agents, tools, identities, "
        "and data assets through typed relationships with source evidence and explicit completeness."
    )
    for name in ("README.md", "DOCKER_HUB_README.md", "site-docs/index.md"):
        assert definition in " ".join((ROOT / name).read_text().split())
    vocabulary = (ROOT / "docs/HOW_IT_WORKS.md").read_text()
    for term in ("`UnifiedGraph`", "`ContextGraph`", "**Mesh**", "**Evidence**", "**Current**", "**Proposed**", "**Difference**"):
        assert term in vocabulary


def test_readme_explains_blast_radius_before_screenshots_without_exploit_claim() -> None:
    readme = (ROOT / "README.md").read_text()
    assert readme.index("### Read the blast radius") < readme.index("correlation-receipts-live.png")
    assert "Vulnerable package → advisory finding" in readme
    assert "credential names alone" in readme
    assert "do not prove permission or exploitability" in readme


def test_readme_grc_names_only_shipped_narrative_mappings() -> None:
    assert {"owasp-llm", "atlas", "eu-ai-act", "nist"} <= set(ALL_FRAMEWORK_SLUGS)
    readme = (ROOT / "README.md").read_text()
    row = next(line for line in readme.splitlines() if line.startswith("| GRC / audit |"))
    for label in ("OWASP LLM Top 10", "MITRE ATLAS", "EU AI Act", "NIST AI RMF"):
        assert label in row
    assert "unavailable, partial, and not-assessed" in row
    assert "findings and reachability are not presented as audit certification" in " ".join(readme.split())
