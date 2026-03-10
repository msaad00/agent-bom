"""Tests for evidence-based MCP server trust scoring with CVE citations."""

from agent_bom.enforcement import EnforcementFinding
from agent_bom.models import MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.trust_score import (
    CategoryScore,
    TrustEvidence,
    _score_capabilities,
    _score_credentials,
    _score_cves,
    _score_drift,
    _score_registry,
    _score_scorecard,
    _score_to_grade,
    calculate_trust_score,
    calculate_trust_scores,
)


def _server(
    name: str = "test-server",
    tools: list[MCPTool] | None = None,
    packages: list[Package] | None = None,
    env: dict[str, str] | None = None,
    registry_verified: bool = False,
) -> MCPServer:
    return MCPServer(
        name=name,
        tools=tools or [],
        packages=packages or [],
        env=env or {},
        registry_verified=registry_verified,
    )


def _vuln(
    vid: str = "CVE-2024-0001",
    severity: Severity = Severity.HIGH,
    fixed_version: str | None = None,
    epss_score: float | None = None,
    is_kev: bool = False,
) -> Vulnerability:
    return Vulnerability(
        id=vid,
        summary="Test vulnerability",
        severity=severity,
        fixed_version=fixed_version,
        epss_score=epss_score,
        is_kev=is_kev,
    )


# -- Grade conversion --------------------------------------------------------


def test_grade_a():
    assert _score_to_grade(95) == "A"


def test_grade_a_boundary():
    assert _score_to_grade(90) == "A"


def test_grade_b():
    assert _score_to_grade(85) == "B"


def test_grade_c():
    assert _score_to_grade(75) == "C"


def test_grade_d():
    assert _score_to_grade(65) == "D"


def test_grade_f():
    assert _score_to_grade(50) == "F"


def test_grade_f_zero():
    assert _score_to_grade(0) == "F"


# -- Clean server (baseline) -------------------------------------------------


def test_clean_server_perfect_score():
    """Server with no tools, no packages, verified registry gets near-perfect score."""
    server = _server(registry_verified=True)
    result = calculate_trust_score(server)
    assert result.overall_score == 100.0
    assert result.grade == "A"
    assert len(result.evidence) == 0


def test_clean_server_unverified_registry():
    """Unverified server gets a small deduction."""
    server = _server(registry_verified=False)
    result = calculate_trust_score(server)
    assert result.overall_score == 95.0
    assert result.grade == "A"
    assert len(result.evidence) == 1
    assert result.evidence[0].category == "registry"


# -- CVE scoring --------------------------------------------------------------


def test_critical_cve_deduction():
    """Critical CVE causes a large deduction."""
    pkg = Package(
        name="lodash",
        version="4.17.20",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2021-23337", Severity.CRITICAL)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    result = calculate_trust_score(server)
    assert result.overall_score < 100
    cve_cat = next(c for c in result.categories if c.category == "cve")
    assert cve_cat.actual_deduction == 8.0
    assert len(cve_cat.evidence) == 1
    assert cve_cat.evidence[0].cve_id == "CVE-2021-23337"


def test_high_cve_deduction():
    """High CVE causes a moderate deduction."""
    pkg = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2024-0002", Severity.HIGH)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    assert cve_cat.actual_deduction == 5.0


def test_medium_cve_deduction():
    """Medium CVE causes a small deduction."""
    pkg = Package(
        name="axios",
        version="0.21.0",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2024-0003", Severity.MEDIUM)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    assert cve_cat.actual_deduction == 2.0


def test_low_cve_deduction():
    """Low CVE causes minimal deduction."""
    pkg = Package(
        name="minimist",
        version="1.2.5",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2024-0004", Severity.LOW)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    assert cve_cat.actual_deduction == 0.5


def test_kev_cve_extra_penalty():
    """CISA KEV CVE gets additional penalty beyond base severity."""
    pkg = Package(
        name="log4j",
        version="2.14.0",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2021-44228", Severity.CRITICAL, is_kev=True)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    # CRITICAL (8) + KEV bonus (3) = 11, but capped at _MAX_CVE_DEDUCTION
    assert cve_cat.actual_deduction == 11.0
    assert "CISA KEV" in cve_cat.evidence[0].description


def test_high_epss_extra_penalty():
    """High EPSS score gets additional penalty."""
    pkg = Package(
        name="requests",
        version="2.25.0",
        ecosystem="pypi",
        vulnerabilities=[_vuln("CVE-2024-0005", Severity.HIGH, epss_score=0.8)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    # HIGH (5) + EPSS bonus (2) = 7
    assert cve_cat.actual_deduction == 7.0
    assert "EPSS" in cve_cat.evidence[0].description


def test_cve_deduction_capped():
    """CVE deductions are capped at max."""
    vulns = [_vuln(f"CVE-2024-{i:04d}", Severity.CRITICAL) for i in range(10)]
    pkg = Package(name="bad-pkg", version="1.0.0", ecosystem="npm", vulnerabilities=vulns)
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    assert cve_cat.actual_deduction <= 35.0


def test_cve_fix_version_in_evidence():
    """Fixed version is included in evidence description."""
    pkg = Package(
        name="lodash",
        version="4.17.20",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2021-23337", Severity.CRITICAL, fixed_version="4.17.21")],
    )
    server = _server(packages=[pkg], registry_verified=True)
    cve_cat = _score_cves(server)
    assert "4.17.21" in cve_cat.evidence[0].description


def test_multiple_packages_with_cves():
    """CVEs across multiple packages are all counted."""
    pkg1 = Package(
        name="lodash",
        version="4.17.20",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2021-23337", Severity.CRITICAL)],
    )
    pkg2 = Package(
        name="express",
        version="4.17.1",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2024-0002", Severity.HIGH)],
    )
    server = _server(packages=[pkg1, pkg2], registry_verified=True)
    cve_cat = _score_cves(server)
    assert len(cve_cat.evidence) == 2
    assert cve_cat.actual_deduction == 13.0  # 8 + 5


def test_no_cves_perfect_category():
    """Server with no vulnerabilities gets full CVE category score."""
    server = _server(registry_verified=True)
    cve_cat = _score_cves(server)
    assert cve_cat.actual_deduction == 0.0
    assert cve_cat.score == 35.0


# -- Credential scoring -------------------------------------------------------


def test_credential_deduction():
    """Server with credential env vars gets deductions."""
    server = _server(
        env={"GITHUB_TOKEN": "ghp_xxx", "AWS_SECRET_ACCESS_KEY": "xxx"},
        registry_verified=True,
    )
    cred_cat = _score_credentials(server)
    assert cred_cat.actual_deduction == 10.0  # 2 creds * 5 each
    assert len(cred_cat.evidence) == 2


def test_no_credentials_perfect():
    """Server with no credentials gets full score."""
    server = _server(env={"PATH": "/usr/bin"}, registry_verified=True)
    cred_cat = _score_credentials(server)
    assert cred_cat.actual_deduction == 0.0
    assert cred_cat.score == 15.0


def test_credential_deduction_capped():
    """Credential deduction is capped at max."""
    env = {f"SECRET_{i}": f"val_{i}" for i in range(10)}
    server = _server(env=env, registry_verified=True)
    cred_cat = _score_credentials(server)
    assert cred_cat.actual_deduction <= 15.0


def test_credential_evidence_names():
    """Credential evidence includes the env var name."""
    server = _server(env={"API_KEY": "xxx"}, registry_verified=True)
    cred_cat = _score_credentials(server)
    assert len(cred_cat.evidence) == 1
    assert "API_KEY" in cred_cat.evidence[0].description


# -- Capability scoring -------------------------------------------------------


def test_execute_capability_deduction():
    """Server with EXECUTE capability tools gets deduction."""
    tools = [MCPTool(name="run_command", description="Execute a shell command")]
    server = _server(tools=tools, registry_verified=True)
    cap_cat = _score_capabilities(server)
    assert cap_cat.actual_deduction > 0
    assert any("EXECUTE" in e.description for e in cap_cat.evidence)


def test_read_only_minimal_deduction():
    """Server with only READ tools gets no capability deduction."""
    tools = [
        MCPTool(name="read_file", description="Read a file"),
        MCPTool(name="list_dir", description="List directory contents"),
    ]
    server = _server(tools=tools, registry_verified=True)
    cap_cat = _score_capabilities(server)
    assert cap_cat.actual_deduction == 0.0


def test_dangerous_combo_extra_deduction():
    """Dangerous capability combination adds extra deduction."""
    tools = [
        MCPTool(name="execute_command", description="Execute a shell command"),
        MCPTool(name="write_file", description="Write content to a file"),
    ]
    server = _server(tools=tools, registry_verified=True)
    cap_cat = _score_capabilities(server)
    # EXECUTE (4) + dangerous combo (EXECUTE+WRITE = 3) = 7 minimum
    assert cap_cat.actual_deduction >= 7.0
    combo_evidence = [e for e in cap_cat.evidence if "combination" in e.description.lower()]
    assert len(combo_evidence) >= 1


def test_no_tools_perfect_capability():
    """Server with no tools gets full capability score."""
    server = _server(registry_verified=True)
    cap_cat = _score_capabilities(server)
    assert cap_cat.actual_deduction == 0.0


# -- Registry scoring ---------------------------------------------------------


def test_unverified_registry_deduction():
    """Unverified server gets 5-point deduction."""
    server = _server(registry_verified=False)
    reg_cat = _score_registry(server)
    assert reg_cat.actual_deduction == 5.0


def test_verified_registry_no_deduction():
    """Verified server with no registry entry gets no deduction."""
    server = _server(registry_verified=True)
    reg_cat = _score_registry(server)
    assert reg_cat.actual_deduction == 0.0


def test_high_risk_registry_deduction():
    """High-risk registry entry gets maximum deduction."""
    server = _server(registry_verified=True)
    reg_cat = _score_registry(server, registry_entry={"risk_level": "high", "risk_justification": "Shell access"})
    assert reg_cat.actual_deduction == 10.0
    assert "HIGH" in reg_cat.evidence[0].description


def test_medium_risk_registry_deduction():
    """Medium-risk registry entry gets moderate deduction."""
    server = _server(registry_verified=True)
    reg_cat = _score_registry(server, registry_entry={"risk_level": "medium"})
    assert reg_cat.actual_deduction == 5.0


def test_low_risk_registry_no_deduction():
    """Low-risk registry entry gets no deduction."""
    server = _server(registry_verified=True)
    reg_cat = _score_registry(server, registry_entry={"risk_level": "low"})
    assert reg_cat.actual_deduction == 0.0


# -- Drift scoring ------------------------------------------------------------


def test_drift_finding_deduction():
    """Drift findings cause deduction."""
    server = _server(registry_verified=True)
    findings = [
        EnforcementFinding(
            severity="high",
            category="drift",
            server_name="test-server",
            tool_name="hidden_tool",
            reason="Undeclared tool 'hidden_tool' found at runtime",
        ),
    ]
    drift_cat = _score_drift(server, findings)
    assert drift_cat.actual_deduction == 4.0
    assert len(drift_cat.evidence) == 1


def test_description_drift_deduction():
    """Description drift causes deduction."""
    server = _server(registry_verified=True)
    findings = [
        EnforcementFinding(
            severity="medium",
            category="description_drift",
            server_name="test-server",
            tool_name="read_file",
            reason="Tool 'read_file' description changed between config and runtime",
        ),
    ]
    drift_cat = _score_drift(server, findings)
    assert drift_cat.actual_deduction == 2.0


def test_injection_finding_in_drift():
    """Injection findings from enforcement are counted in drift category."""
    server = _server(registry_verified=True)
    findings = [
        EnforcementFinding(
            severity="high",
            category="injection",
            server_name="test-server",
            tool_name="evil_tool",
            reason="Tool description contains injection pattern",
        ),
    ]
    drift_cat = _score_drift(server, findings)
    assert drift_cat.actual_deduction == 5.0


def test_no_drift_findings_perfect():
    """No enforcement findings gives full drift score."""
    server = _server(registry_verified=True)
    drift_cat = _score_drift(server, [])
    assert drift_cat.actual_deduction == 0.0


def test_drift_ignores_other_servers():
    """Drift findings for other servers are ignored."""
    server = _server(name="my-server", registry_verified=True)
    findings = [
        EnforcementFinding(
            severity="high",
            category="drift",
            server_name="other-server",
            tool_name="hidden_tool",
            reason="Undeclared tool",
        ),
    ]
    drift_cat = _score_drift(server, findings)
    assert drift_cat.actual_deduction == 0.0


# -- Scorecard scoring --------------------------------------------------------


def test_low_scorecard_deduction():
    """Package with low scorecard score gets deduction."""
    pkg = Package(name="risky-pkg", version="1.0.0", ecosystem="npm", scorecard_score=2.0)
    server = _server(packages=[pkg], registry_verified=True)
    sc_cat = _score_scorecard(server)
    assert sc_cat.actual_deduction == 5.0
    assert "poorly maintained" in sc_cat.evidence[0].description


def test_medium_scorecard_deduction():
    """Package with medium scorecard score gets moderate deduction."""
    pkg = Package(name="mid-pkg", version="1.0.0", ecosystem="npm", scorecard_score=4.0)
    server = _server(packages=[pkg], registry_verified=True)
    sc_cat = _score_scorecard(server)
    assert sc_cat.actual_deduction == 3.0


def test_moderate_scorecard_deduction():
    """Package with moderate scorecard score gets small deduction."""
    pkg = Package(name="ok-pkg", version="1.0.0", ecosystem="npm", scorecard_score=6.0)
    server = _server(packages=[pkg], registry_verified=True)
    sc_cat = _score_scorecard(server)
    assert sc_cat.actual_deduction == 1.0


def test_good_scorecard_no_deduction():
    """Package with good scorecard score gets no deduction."""
    pkg = Package(name="good-pkg", version="1.0.0", ecosystem="npm", scorecard_score=8.0)
    server = _server(packages=[pkg], registry_verified=True)
    sc_cat = _score_scorecard(server)
    assert sc_cat.actual_deduction == 0.0


def test_no_scorecard_no_deduction():
    """Packages without scorecard data get no deduction."""
    pkg = Package(name="no-sc-pkg", version="1.0.0", ecosystem="npm")
    server = _server(packages=[pkg], registry_verified=True)
    sc_cat = _score_scorecard(server)
    assert sc_cat.actual_deduction == 0.0


# -- Integration tests --------------------------------------------------------


def test_full_score_all_signals():
    """Server with multiple risk signals gets appropriate aggregate score."""
    vuln = _vuln("CVE-2024-1234", Severity.CRITICAL)
    pkg = Package(
        name="bad-pkg",
        version="1.0.0",
        ecosystem="npm",
        vulnerabilities=[vuln],
        scorecard_score=2.5,
    )
    tools = [
        MCPTool(name="execute_command", description="Execute shell command"),
        MCPTool(name="write_file", description="Write file"),
    ]
    server = _server(
        name="risky-server",
        tools=tools,
        packages=[pkg],
        env={"API_KEY": "secret123"},
        registry_verified=False,
    )
    result = calculate_trust_score(
        server,
        registry_entry={"risk_level": "high", "risk_justification": "Shell access"},
    )
    # Should have significant deductions across multiple categories
    assert result.overall_score < 65
    assert result.grade in ("D", "F")
    assert len(result.evidence) >= 4  # At least one from each scoring category


def test_serialization_to_dict():
    """TrustScoreResult.to_dict() produces valid structure."""
    server = _server(registry_verified=True)
    result = calculate_trust_score(server)
    d = result.to_dict()
    assert "overall_score" in d
    assert "grade" in d
    assert "categories" in d
    assert "evidence" in d
    assert "summary" in d
    assert d["grade"] == "A"


def test_category_score_to_dict():
    """CategoryScore.to_dict() produces valid structure."""
    cat = CategoryScore(
        category="cve",
        max_deduction=35.0,
        actual_deduction=8.0,
        score=27.0,
        evidence=[
            TrustEvidence(
                category="cve",
                description="CVE-2024-0001",
                deduction=8.0,
                severity="critical",
                cve_id="CVE-2024-0001",
            ),
        ],
    )
    d = cat.to_dict()
    assert d["category"] == "cve"
    assert d["max_points"] == 35.0
    assert d["deduction"] == 8.0
    assert d["evidence_count"] == 1


def test_evidence_to_dict_optional_fields():
    """TrustEvidence.to_dict() omits None optional fields."""
    ev = TrustEvidence(
        category="cve",
        description="test",
        deduction=1.0,
        severity="high",
        cve_id="CVE-2024-0001",
    )
    d = ev.to_dict()
    assert "cve_id" in d
    assert "tool_name" not in d
    assert "package_name" not in d


def test_evidence_to_dict_all_fields():
    """TrustEvidence.to_dict() includes all set fields."""
    ev = TrustEvidence(
        category="cve",
        description="test",
        deduction=1.0,
        severity="high",
        cve_id="CVE-2024-0001",
        package_name="lodash",
        package_version="4.17.20",
        tool_name="read_file",
    )
    d = ev.to_dict()
    assert d["cve_id"] == "CVE-2024-0001"
    assert d["package_name"] == "lodash"
    assert d["package_version"] == "4.17.20"
    assert d["tool_name"] == "read_file"


def test_calculate_trust_scores_multiple_servers():
    """calculate_trust_scores handles multiple servers."""
    servers = [
        _server(name="clean", registry_verified=True),
        _server(
            name="dirty",
            packages=[
                Package(
                    name="bad",
                    version="1.0.0",
                    ecosystem="npm",
                    vulnerabilities=[_vuln("CVE-2024-9999", Severity.CRITICAL)],
                ),
            ],
            registry_verified=True,
        ),
    ]
    results = calculate_trust_scores(servers)
    assert len(results) == 2
    assert results[0].overall_score > results[1].overall_score
    assert results[0].server_name == "clean"
    assert results[1].server_name == "dirty"


def test_calculate_trust_scores_with_registry():
    """calculate_trust_scores uses registry entries when provided."""
    servers = [_server(name="fs-server", registry_verified=True)]
    registry = {"fs-server": {"risk_level": "high", "risk_justification": "Shell"}}
    results = calculate_trust_scores(servers, registry=registry)
    assert len(results) == 1
    assert results[0].overall_score < 100


def test_calculate_trust_scores_empty():
    """calculate_trust_scores handles empty list."""
    results = calculate_trust_scores([])
    assert results == []


def test_summary_contains_cve_citations():
    """Summary text includes CVE IDs when present."""
    pkg = Package(
        name="lodash",
        version="4.17.20",
        ecosystem="npm",
        vulnerabilities=[_vuln("CVE-2021-23337", Severity.CRITICAL)],
    )
    server = _server(packages=[pkg], registry_verified=True)
    result = calculate_trust_score(server)
    assert "CVE-2021-23337" in result.summary


def test_summary_clean_server():
    """Summary for clean server says no issues found."""
    server = _server(registry_verified=True)
    result = calculate_trust_score(server)
    assert "No critical or high-severity issues" in result.summary


def test_evidence_sorted_by_deduction():
    """Evidence list is sorted by deduction (highest first)."""
    pkg = Package(
        name="multi-vuln",
        version="1.0.0",
        ecosystem="npm",
        vulnerabilities=[
            _vuln("CVE-2024-0001", Severity.LOW),
            _vuln("CVE-2024-0002", Severity.CRITICAL),
        ],
    )
    server = _server(packages=[pkg], registry_verified=True)
    result = calculate_trust_score(server)
    cve_evidence = [e for e in result.evidence if e.category == "cve"]
    if len(cve_evidence) >= 2:
        assert cve_evidence[0].deduction >= cve_evidence[1].deduction


def test_overall_score_never_negative():
    """Overall score is clamped to 0 minimum."""
    vulns = [_vuln(f"CVE-2024-{i:04d}", Severity.CRITICAL, is_kev=True) for i in range(10)]
    pkg = Package(name="terrible-pkg", version="0.1.0", ecosystem="npm", vulnerabilities=vulns)
    tools = [
        MCPTool(name="execute_command", description="Execute shell"),
        MCPTool(name="delete_all", description="Delete everything"),
        MCPTool(name="admin_panel", description="Admin configuration"),
    ]
    server = _server(
        name="worst-server",
        tools=tools,
        packages=[pkg],
        env={"SECRET_KEY": "x", "API_TOKEN": "y", "DB_PASSWORD": "z", "AUTH_SECRET": "w"},
        registry_verified=False,
    )
    findings = [
        EnforcementFinding(
            severity="critical", category="injection", server_name="worst-server", tool_name="execute_command", reason="Injection detected"
        ),
        EnforcementFinding(severity="high", category="drift", server_name="worst-server", tool_name="hidden", reason="Undeclared tool"),
    ]
    result = calculate_trust_score(server, enforcement_findings=findings)
    assert result.overall_score >= 0
    assert result.grade == "F"


def test_six_categories_always_present():
    """Result always has exactly 6 categories."""
    server = _server(registry_verified=True)
    result = calculate_trust_score(server)
    assert len(result.categories) == 6
    category_names = {c.category for c in result.categories}
    assert category_names == {"cve", "credential", "capability", "registry", "drift", "scorecard"}
