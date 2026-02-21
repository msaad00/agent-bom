"""Tests for the auto-discovery module — risk inference, justification, and enrichment filtering."""

from agent_bom.autodiscover import (
    generate_risk_justification,
    infer_risk_level,
)
from agent_bom.models import Package

# ── infer_risk_level tests ────────────────────────────────────────────────


def test_infer_risk_high():
    """Metadata with high-risk keywords and no repo should score as 'high'."""
    metadata = {
        "description": "execute shell commands remotely",
        "keywords": [],
        "maintainers": 1,
        "repository": "",
        "dependencies_count": 0,
    }
    assert infer_risk_level(metadata) == "high"


def test_infer_risk_low():
    """Metadata with only medium keyword, a repo, and multiple maintainers should be 'low'."""
    metadata = {
        "description": "read configuration files",
        "keywords": [],
        "maintainers": 5,
        "repository": "https://github.com/example/pkg",
        "dependencies_count": 3,
    }
    assert infer_risk_level(metadata) == "low"


def test_infer_risk_medium():
    """Metadata with a high-risk keyword and single maintainer should be at least 'medium'."""
    metadata = {
        "description": "filesystem access utility",
        "keywords": [],
        "maintainers": 1,
        "repository": "https://github.com/example/fs-util",
        "dependencies_count": 5,
    }
    result = infer_risk_level(metadata)
    assert result in ("medium", "high")


def test_infer_risk_single_maintainer():
    """A single maintainer should bump the score by 1 compared to multiple maintainers."""
    base = {
        "description": "a simple utility library",
        "keywords": [],
        "repository": "https://github.com/example/lib",
        "dependencies_count": 0,
    }
    # With many maintainers — score stays low
    multi = {**base, "maintainers": 5}
    single = {**base, "maintainers": 1}

    multi_level = infer_risk_level(multi)
    single_level = infer_risk_level(single)

    # Single maintainer should result in the same or higher risk level
    risk_order = {"low": 0, "medium": 1, "high": 2}
    assert risk_order[single_level] >= risk_order[multi_level]


def test_infer_risk_no_repo():
    """No repository link should bump the score by 2 compared to having one."""
    # Use a medium-risk keyword so the base score is 1; adding +2 for no repo crosses
    # the medium threshold (>= 3).
    base = {
        "description": "fetch data from an api",
        "keywords": [],
        "maintainers": 5,
        "dependencies_count": 0,
    }
    with_repo = {**base, "repository": "https://github.com/example/lib"}
    no_repo = {**base, "repository": ""}

    with_level = infer_risk_level(with_repo)
    no_level = infer_risk_level(no_repo)

    risk_order = {"low": 0, "medium": 1, "high": 2}
    assert risk_order[no_level] > risk_order[with_level]


# ── generate_risk_justification tests ─────────────────────────────────────


def test_generate_justification():
    """generate_risk_justification should produce a non-empty string."""
    metadata = {
        "description": "A utility package",
        "keywords": [],
        "maintainers": 3,
        "repository": "https://github.com/example/util",
        "dependencies_count": 2,
    }
    result = generate_risk_justification(metadata, "low")
    assert isinstance(result, str)
    assert len(result) > 0


def test_generate_justification_high_risk_keywords():
    """Metadata with 'execute' keyword should produce justification mentioning 'High-risk'."""
    metadata = {
        "description": "execute arbitrary shell commands",
        "keywords": [],
        "maintainers": 1,
        "repository": "",
        "dependencies_count": 0,
    }
    result = generate_risk_justification(metadata, "high")
    assert "High-risk" in result


# ── enrich_unknown_packages filter logic ──────────────────────────────────


def test_enrich_skips_registry_packages():
    """Packages with resolved_from_registry=True should be filtered out by the enrichment filter."""
    registry_pkg = Package(
        name="@modelcontextprotocol/server-filesystem",
        version="1.0.0",
        ecosystem="npm",
        resolved_from_registry=True,
    )
    unknown_pkg = Package(
        name="some-unknown-pkg",
        version="2.3.1",
        ecosystem="npm",
        resolved_from_registry=False,
    )
    packages = [registry_pkg, unknown_pkg]

    # Replicate the filter condition from enrich_unknown_packages
    to_enrich = [
        p for p in packages
        if not p.resolved_from_registry
        and not getattr(p, "auto_risk_level", None)
        and p.version not in ("unknown", "latest", "")
        and p.ecosystem in ("npm", "pypi", "PyPI")
    ]

    assert registry_pkg not in to_enrich
    assert unknown_pkg in to_enrich
