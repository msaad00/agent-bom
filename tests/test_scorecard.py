"""Tests for OpenSSF Scorecard enrichment module."""


from agent_bom.models import (
    Agent,
    AgentType,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.scorecard import (
    _repo_url_from_package,
    extract_github_repo,
)

# ─── extract_github_repo ─────────────────────────────────────────────────────


def test_extract_github_repo_https():
    assert extract_github_repo("https://github.com/expressjs/express") == "expressjs/express"


def test_extract_github_repo_https_git_suffix():
    assert extract_github_repo("https://github.com/expressjs/express.git") == "expressjs/express"


def test_extract_github_repo_http():
    assert extract_github_repo("http://github.com/owner/repo") == "owner/repo"


def test_extract_github_repo_tree_path():
    assert extract_github_repo("https://github.com/owner/repo/tree/main") == "owner/repo"


def test_extract_github_repo_hash_fragment():
    assert extract_github_repo("https://github.com/owner/repo#readme") == "owner/repo"


def test_extract_github_repo_query():
    assert extract_github_repo("https://github.com/owner/repo?tab=readme") == "owner/repo"


def test_extract_github_repo_no_protocol():
    assert extract_github_repo("github.com/owner/repo") == "owner/repo"


def test_extract_github_repo_not_github():
    assert extract_github_repo("https://gitlab.com/owner/repo") is None


def test_extract_github_repo_invalid():
    assert extract_github_repo("not a url") is None


def test_extract_github_repo_empty():
    assert extract_github_repo("") is None


def test_extract_github_repo_trailing_slash():
    assert extract_github_repo("https://github.com/owner/repo/") == "owner/repo"


# ─── _repo_url_from_package ─────────────────────────────────────────────────


def test_repo_from_source_repo():
    pkg = Package(name="express", version="4.18.2", ecosystem="npm",
                  source_repo="https://github.com/expressjs/express")
    assert _repo_url_from_package(pkg) == "expressjs/express"


def test_repo_from_purl_with_github():
    pkg = Package(name="express", version="4.18.2", ecosystem="npm",
                  purl="pkg:npm/express@4.18.2?repository_url=github.com/expressjs/express")
    assert _repo_url_from_package(pkg) == "expressjs/express"


def test_repo_from_package_no_repo():
    pkg = Package(name="express", version="4.18.2", ecosystem="npm")
    assert _repo_url_from_package(pkg) is None


def test_repo_from_package_non_github():
    pkg = Package(name="lib", version="1.0", ecosystem="npm",
                  source_repo="https://gitlab.com/owner/repo")
    assert _repo_url_from_package(pkg) is None


# ─── Scorecard risk score modifier ──────────────────────────────────────────


def _make_br(scorecard_score=None):
    """Create a minimal BlastRadius for testing."""
    pkg = Package(name="test-pkg", version="1.0.0", ecosystem="npm",
                  scorecard_score=scorecard_score)
    vuln = Vulnerability(id="CVE-2024-1234", summary="Test", severity=Severity.HIGH)
    server = MCPServer(name="test-server")
    agent = Agent(name="test-agent", agent_type=AgentType.CLAUDE_DESKTOP,
                  config_path="/tmp/test", mcp_servers=[server])
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_risk_score_no_scorecard():
    br = _make_br(scorecard_score=None)
    score = br.calculate_risk_score()
    assert score > 0
    base_score = score

    # No scorecard = no boost
    br2 = _make_br(scorecard_score=None)
    br2.calculate_risk_score()
    assert br2.risk_score == base_score


def test_risk_score_high_scorecard_no_boost():
    """Score >= 7.0 should not add any scorecard boost."""
    br = _make_br(scorecard_score=8.5)
    score = br.calculate_risk_score()

    br_none = _make_br(scorecard_score=None)
    base = br_none.calculate_risk_score()

    assert score == base  # No boost for high scorecard


def test_risk_score_medium_scorecard_small_boost():
    """Score 5.0-6.9 should add 0.25 boost."""
    br = _make_br(scorecard_score=5.5)
    score = br.calculate_risk_score()

    br_none = _make_br(scorecard_score=None)
    base = br_none.calculate_risk_score()

    assert score == base + 0.25


def test_risk_score_low_scorecard_medium_boost():
    """Score 3.0-4.9 should add 0.5 boost."""
    br = _make_br(scorecard_score=4.0)
    score = br.calculate_risk_score()

    br_none = _make_br(scorecard_score=None)
    base = br_none.calculate_risk_score()

    assert score == base + 0.5


def test_risk_score_very_low_scorecard_high_boost():
    """Score < 3.0 should add 0.75 boost."""
    br = _make_br(scorecard_score=2.0)
    score = br.calculate_risk_score()

    br_none = _make_br(scorecard_score=None)
    base = br_none.calculate_risk_score()

    assert score == base + 0.75


def test_risk_score_capped_at_10():
    """Risk score should never exceed 10.0."""
    pkg = Package(name="test", version="1.0", ecosystem="npm", scorecard_score=1.0)
    vuln = Vulnerability(id="CVE-2024-9999", summary="Test", severity=Severity.CRITICAL,
                         epss_score=0.95, is_kev=True)
    server = MCPServer(name="srv")
    agent = Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP,
                  config_path="/tmp", mcp_servers=[server])
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent, agent, agent, agent],
        exposed_credentials=["TOKEN1", "TOKEN2", "TOKEN3", "TOKEN4", "TOKEN5"],
        exposed_tools=[],
        ai_risk_context="AI framework",
    )
    score = br.calculate_risk_score()
    assert score == 10.0


# ─── Package model fields ──────────────────────────────────────────────────


def test_package_scorecard_defaults():
    pkg = Package(name="test", version="1.0", ecosystem="npm")
    assert pkg.scorecard_score is None
    assert pkg.scorecard_checks == {}


def test_package_scorecard_settable():
    pkg = Package(
        name="express",
        version="4.18.2",
        ecosystem="npm",
        scorecard_score=7.5,
        scorecard_checks={"Code-Review": 8, "Maintained": 10, "Vulnerabilities": 9},
    )
    assert pkg.scorecard_score == 7.5
    assert pkg.scorecard_checks["Maintained"] == 10
    assert len(pkg.scorecard_checks) == 3
