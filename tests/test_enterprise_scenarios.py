"""Tests for enterprise scenario enhancements.

Covers: posture scorecard, credential risk ranking, incident correlation,
Slack blast radius enrichment, and new policy conditions.
"""

from __future__ import annotations

# ── Helpers ──────────────────────────────────────────────────────────────────


def _make_vuln(
    vuln_id="CVE-2025-0001",
    severity="HIGH",
    cvss_score=7.5,
    fixed_version="1.2.3",
    is_kev=False,
    epss_score=None,
    nvd_published=None,
):
    from agent_bom.models import Severity, Vulnerability

    sev_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
    }
    return Vulnerability(
        id=vuln_id,
        summary=f"Test vuln {vuln_id}",
        severity=sev_map.get(severity, Severity.MEDIUM),
        cvss_score=cvss_score,
        fixed_version=fixed_version,
        is_kev=is_kev,
        epss_score=epss_score,
        nvd_published=nvd_published,
    )


def _make_package(name="test-pkg", version="1.0.0", ecosystem="npm", scorecard_score=None, is_malicious=False):
    from agent_bom.models import Package

    return Package(
        name=name,
        version=version,
        ecosystem=ecosystem,
        scorecard_score=scorecard_score,
        is_malicious=is_malicious,
    )


def _make_server(name="test-server", env=None, packages=None, tools=None, registry_verified=False):
    from agent_bom.models import MCPServer, MCPTool
    from agent_bom.models import TransportType as Transport

    return MCPServer(
        name=name,
        command="node",
        args=["server.js"],
        transport=Transport.STDIO,
        env=env or {},
        packages=packages or [],
        tools=tools or [MCPTool(name="tool1", description="Test tool")],
        registry_verified=registry_verified,
    )


def _make_agent(name="test-agent", servers=None):
    from agent_bom.models import Agent, AgentType

    return Agent(
        name=name,
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/home/user/.claude",
        mcp_servers=servers or [],
    )


def _make_blast_radius(vuln=None, pkg=None, agents=None, servers=None, creds=None, tools=None):
    from agent_bom.models import BlastRadius

    v = vuln or _make_vuln()
    p = pkg or _make_package()
    br = BlastRadius(
        vulnerability=v,
        package=p,
        affected_servers=servers or [],
        affected_agents=agents or [],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )
    br.calculate_risk_score()
    return br


def _make_report(agents=None, blast_radii=None):
    from agent_bom.models import AIBOMReport

    return AIBOMReport(
        agents=agents or [],
        blast_radii=blast_radii or [],
    )


# ── Posture Scorecard ────────────────────────────────────────────────────────


class TestPostureScorecard:
    def test_clean_report_good_grade(self):
        """Clean report (no vulns) should get a good grade (A or B)."""
        from agent_bom.posture import compute_posture_scorecard

        report = _make_report()
        sc = compute_posture_scorecard(report)
        assert sc.grade in ("A", "B")
        assert sc.score >= 75

    def test_critical_vulns_lower_score(self):
        """Critical vulnerabilities should significantly reduce score."""
        from agent_bom.posture import compute_posture_scorecard

        vuln = _make_vuln(severity="CRITICAL")
        br = _make_blast_radius(vuln=vuln)
        report = _make_report(blast_radii=[br])
        sc = compute_posture_scorecard(report)
        assert sc.score < 100
        assert "vulnerability_posture" in sc.dimensions

    def test_kev_penalizes_exploitation_dimension(self):
        """KEV vulns should penalize active exploitation dimension."""
        from agent_bom.posture import compute_posture_scorecard

        vuln = _make_vuln(is_kev=True)
        br = _make_blast_radius(vuln=vuln)
        report = _make_report(blast_radii=[br])
        sc = compute_posture_scorecard(report)
        assert sc.dimensions["active_exploitation"].score < 100

    def test_credential_exposure_penalizes(self):
        """Credential exposure should reduce credential hygiene score."""
        from agent_bom.posture import compute_posture_scorecard

        server = _make_server(env={"API_KEY": "secret", "DB_PASSWORD": "pass"})
        agent = _make_agent(servers=[server])
        report = _make_report(agents=[agent])
        sc = compute_posture_scorecard(report)
        assert sc.dimensions["credential_hygiene"].score < 100

    def test_scorecard_coverage(self):
        """OpenSSF Scorecard data should affect supply chain quality."""
        from agent_bom.posture import compute_posture_scorecard

        pkg = _make_package(scorecard_score=8.5)
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        report = _make_report(agents=[agent])
        sc = compute_posture_scorecard(report)
        assert sc.dimensions["supply_chain_quality"].score > 50

    def test_no_scorecard_neutral(self):
        """No scorecard data should give neutral supply chain score."""
        from agent_bom.posture import compute_posture_scorecard

        report = _make_report()
        sc = compute_posture_scorecard(report)
        assert sc.dimensions["supply_chain_quality"].score == 50.0

    def test_grade_boundaries(self):
        """Score-to-grade mapping should follow standard boundaries."""
        from agent_bom.posture import _score_to_grade

        assert _score_to_grade(95) == "A"
        assert _score_to_grade(90) == "A"
        assert _score_to_grade(85) == "B"
        assert _score_to_grade(80) == "B"
        assert _score_to_grade(75) == "C"
        assert _score_to_grade(65) == "D"
        assert _score_to_grade(55) == "F"
        assert _score_to_grade(0) == "F"

    def test_to_dict_format(self):
        """Scorecard to_dict should have expected keys."""
        from agent_bom.posture import compute_posture_scorecard

        report = _make_report()
        sc = compute_posture_scorecard(report)
        d = sc.to_dict()
        assert "grade" in d
        assert "score" in d
        assert "summary" in d
        assert "dimensions" in d
        for dim in d["dimensions"].values():
            assert "name" in dim
            assert "score" in dim
            assert "weight" in dim
            assert "weighted_score" in dim

    def test_many_vulns_degrade_grade(self):
        """Many critical vulns should produce grade F."""
        from agent_bom.posture import compute_posture_scorecard

        brs = [_make_blast_radius(vuln=_make_vuln(vuln_id=f"CVE-2025-{i:04d}", severity="CRITICAL")) for i in range(10)]
        report = _make_report(blast_radii=brs)
        sc = compute_posture_scorecard(report)
        assert sc.grade in ("D", "F")

    def test_fixable_vulns_bonus(self):
        """Fixable vulns should give a small bonus over unfixable."""
        from agent_bom.posture import compute_posture_scorecard

        fixable_br = _make_blast_radius(vuln=_make_vuln(fixed_version="2.0.0"))
        unfixable_br = _make_blast_radius(vuln=_make_vuln(vuln_id="CVE-2025-0002", fixed_version=None))
        fixable_report = _make_report(blast_radii=[fixable_br])
        unfixable_report = _make_report(blast_radii=[unfixable_br])
        sc_fix = compute_posture_scorecard(fixable_report)
        sc_nofix = compute_posture_scorecard(unfixable_report)
        assert sc_fix.dimensions["vulnerability_posture"].score >= sc_nofix.dimensions["vulnerability_posture"].score

    def test_filesystem_only_scans_do_not_fail_configuration_quality(self):
        """Filesystem-only scans should treat MCP config quality as not applicable."""
        from agent_bom.models import Agent, AgentType, MCPServer, Package, ServerSurface, Severity, Vulnerability
        from agent_bom.posture import compute_posture_scorecard
        from agent_bom.vuln_compliance import tag_vulnerability

        pkg = Package(name="langchain", version="0.1.0", ecosystem="pypi")
        vuln = Vulnerability(id="CVE-2026-1000", summary="demo", severity=Severity.HIGH)
        vuln.compliance_tags = tag_vulnerability(vuln, pkg)
        br = _make_blast_radius(pkg=pkg, vuln=vuln)

        fs_server = MCPServer(name="filesystem:repo", command="", packages=[pkg], surface=ServerSurface.FILESYSTEM)
        fs_agent = Agent(name="filesystem:repo", agent_type=AgentType.CUSTOM, config_path=".", mcp_servers=[fs_server])
        report = _make_report(agents=[fs_agent], blast_radii=[br])

        sc = compute_posture_scorecard(report)
        assert sc.dimensions["configuration_quality"].score == 100.0
        assert "N/A" in sc.dimensions["configuration_quality"].details
        assert sc.dimensions["compliance_coverage"].score > 0

    def test_weak_grade_summary_explains_real_credential_exposure(self):
        """Weak grades should explain when credential/config risk is the real cause."""
        from agent_bom.posture import compute_posture_scorecard

        server = _make_server(
            registry_verified=False,
            tools=[],
            env={"API_KEY": "secret", "DB_PASSWORD": "pass", "SLACK_TOKEN": "token"},
        )
        agent = _make_agent(servers=[server])
        brs = [
            _make_blast_radius(
                vuln=_make_vuln(vuln_id=f"CVE-2026-{i:04d}", severity="CRITICAL"),
                agents=[agent],
                servers=[server],
                creds=["API_KEY"],
            )
            for i in range(3)
        ]
        report = _make_report(agents=[agent], blast_radii=brs)

        sc = compute_posture_scorecard(report)
        assert sc.grade in ("D", "F")
        assert "credential exposure" in sc.summary
        assert "MCP configuration" in sc.summary


# ── Credential Risk Ranking ──────────────────────────────────────────────────


class TestCredentialRiskRanking:
    def test_empty_report_empty_ranking(self):
        """No blast radii → empty ranking."""
        from agent_bom.posture import compute_credential_risk_ranking

        report = _make_report()
        ranking = compute_credential_risk_ranking(report)
        assert ranking == []

    def test_critical_vuln_credential_ranks_critical(self):
        """Credential exposed via critical vuln should rank as critical tier."""
        from agent_bom.posture import compute_credential_risk_ranking

        vuln = _make_vuln(severity="CRITICAL")
        br = _make_blast_radius(vuln=vuln, creds=["API_KEY"])
        report = _make_report(blast_radii=[br])
        ranking = compute_credential_risk_ranking(report)
        assert len(ranking) == 1
        assert ranking[0]["credential"] == "API_KEY"
        assert ranking[0]["risk_tier"] == "critical"

    def test_multiple_creds_sorted_by_risk(self):
        """Multiple credentials should be sorted by risk tier."""
        from agent_bom.posture import compute_credential_risk_ranking

        crit_br = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0001", severity="CRITICAL"),
            creds=["DB_PASSWORD"],
        )
        low_br = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0002", severity="LOW"),
            creds=["LOG_TOKEN"],
        )
        report = _make_report(blast_radii=[crit_br, low_br])
        ranking = compute_credential_risk_ranking(report)
        assert len(ranking) == 2
        assert ranking[0]["credential"] == "DB_PASSWORD"
        assert ranking[0]["risk_tier"] == "critical"

    def test_credential_aggregates_across_blast_radii(self):
        """Same credential in multiple blast radii should aggregate counts."""
        from agent_bom.posture import compute_credential_risk_ranking

        br1 = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0001", severity="HIGH"),
            creds=["API_KEY"],
        )
        br2 = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0002", severity="HIGH"),
            creds=["API_KEY"],
        )
        report = _make_report(blast_radii=[br1, br2])
        ranking = compute_credential_risk_ranking(report)
        assert len(ranking) == 1
        assert ranking[0]["vuln_total"] == 2


# ── Incident Correlation ─────────────────────────────────────────────────────


class TestIncidentCorrelation:
    def test_empty_report_no_incidents(self):
        """No blast radii → no incidents."""
        from agent_bom.posture import compute_incident_correlation

        report = _make_report()
        incidents = compute_incident_correlation(report)
        assert incidents == []

    def test_kev_triggers_p1(self):
        """KEV vulnerability should trigger P1 priority."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        vuln = _make_vuln(is_kev=True)
        br = _make_blast_radius(vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        incidents = compute_incident_correlation(report)
        assert len(incidents) == 1
        assert incidents[0]["priority"] == "P1"

    def test_critical_with_creds_triggers_p2(self):
        """Critical vuln with credentials should be P2."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        vuln = _make_vuln(severity="CRITICAL")
        br = _make_blast_radius(vuln=vuln, agents=[agent], creds=["SECRET"])
        report = _make_report(agents=[agent], blast_radii=[br])
        incidents = compute_incident_correlation(report)
        assert incidents[0]["priority"] == "P2"

    def test_high_only_triggers_p3(self):
        """High-severity only (no creds) should be P3."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        vuln = _make_vuln(severity="HIGH")
        br = _make_blast_radius(vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        incidents = compute_incident_correlation(report)
        assert incidents[0]["priority"] == "P3"

    def test_low_only_triggers_p4(self):
        """Low-severity only should be P4."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        vuln = _make_vuln(severity="LOW")
        br = _make_blast_radius(vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        incidents = compute_incident_correlation(report)
        assert incidents[0]["priority"] == "P4"

    def test_multiple_agents_sorted_by_priority(self):
        """Multiple agents should be sorted P1 first."""
        from agent_bom.posture import compute_incident_correlation

        agent1 = _make_agent(name="safe-agent")
        agent2 = _make_agent(name="risky-agent")
        br1 = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0001", severity="LOW"),
            agents=[agent1],
        )
        br2 = _make_blast_radius(
            vuln=_make_vuln(vuln_id="CVE-2025-0002", is_kev=True),
            agents=[agent2],
        )
        report = _make_report(agents=[agent1, agent2], blast_radii=[br1, br2])
        incidents = compute_incident_correlation(report)
        assert incidents[0]["agent_name"] == "risky-agent"
        assert incidents[0]["priority"] == "P1"

    def test_incident_has_recommended_action(self):
        """Each incident should have a recommended_action field."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        br = _make_blast_radius(vuln=_make_vuln(), agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        incidents = compute_incident_correlation(report)
        assert "recommended_action" in incidents[0]
        assert len(incidents[0]["recommended_action"]) > 0

    def test_incident_aggregates_cves(self):
        """Incident should aggregate unique CVEs across blast radii."""
        from agent_bom.posture import compute_incident_correlation

        agent = _make_agent()
        br1 = _make_blast_radius(vuln=_make_vuln(vuln_id="CVE-2025-0001"), agents=[agent])
        br2 = _make_blast_radius(vuln=_make_vuln(vuln_id="CVE-2025-0002"), agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br1, br2])
        incidents = compute_incident_correlation(report)
        assert len(incidents[0]["unique_cves"]) == 2


# ── Slack Blast Radius Enrichment ────────────────────────────────────────────


class TestSlackBlastRadiusEnrichment:
    def test_basic_slack_payload(self):
        """Basic alert should produce valid Slack payload."""
        from agent_bom.alerts.dispatcher import _build_slack_payload

        alert = {
            "severity": "critical",
            "message": "Test alert",
            "detector": "scan_cve",
            "ts": "2025-01-01T00:00:00Z",
        }
        payload = _build_slack_payload(alert)
        assert "blocks" in payload
        assert len(payload["blocks"]) >= 2

    def test_enriched_slack_payload_with_blast_radius(self):
        """Alert with blast radius details should include enrichment block."""
        from agent_bom.alerts.dispatcher import _build_slack_payload

        alert = {
            "severity": "critical",
            "message": "CVE-2025-0001 in test-pkg",
            "detector": "scan_cve",
            "ts": "2025-01-01T00:00:00Z",
            "details": {
                "risk_score": 9.5,
                "affected_agents": ["agent-1", "agent-2"],
                "credentials_exposed": ["API_KEY", "DB_PASSWORD"],
                "fixed_version": "2.0.0",
            },
        }
        payload = _build_slack_payload(alert)
        assert len(payload["blocks"]) == 3  # header + enrichment + context
        enrichment_text = payload["blocks"][1]["text"]["text"]
        assert "9.5" in enrichment_text
        assert "agent-1" in enrichment_text
        assert "API_KEY" in enrichment_text
        assert "2.0.0" in enrichment_text

    def test_no_enrichment_without_details(self):
        """Alert without details should have only 2 blocks."""
        from agent_bom.alerts.dispatcher import _build_slack_payload

        alert = {
            "severity": "high",
            "message": "Simple alert",
            "detector": "test",
            "ts": "2025-01-01T00:00:00Z",
        }
        payload = _build_slack_payload(alert)
        assert len(payload["blocks"]) == 2

    def test_enrichment_with_partial_details(self):
        """Alert with only some details should still show enrichment."""
        from agent_bom.alerts.dispatcher import _build_slack_payload

        alert = {
            "severity": "high",
            "message": "Partial details",
            "detector": "scan_cve",
            "ts": "2025-01-01T00:00:00Z",
            "details": {"risk_score": 7.0},
        }
        payload = _build_slack_payload(alert)
        assert len(payload["blocks"]) == 3
        assert "7.0" in payload["blocks"][1]["text"]["text"]


# ── Scan Alert Enrichment ────────────────────────────────────────────────────


class TestScanAlertEnrichment:
    def test_kev_alert_has_blast_radius_fields(self):
        """KEV scan alert should include affected_agents and credentials."""
        from agent_bom.alerts.scan_alerts import alerts_from_scan_result

        report = {
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-2025-0001",
                    "severity": "critical",
                    "is_kev": True,
                    "package": "test-pkg",
                    "risk_score": 9.0,
                    "affected_agents": ["agent-1"],
                    "exposed_credentials": ["API_KEY"],
                    "fixed_version": "2.0.0",
                    "cvss_score": 9.8,
                    "epss_score": 0.95,
                }
            ],
            "agents": [],
        }
        alerts = alerts_from_scan_result(report)
        assert len(alerts) == 1
        details = alerts[0]["details"]
        assert details["affected_agents"] == ["agent-1"]
        assert details["credentials_exposed"] == ["API_KEY"]
        assert details["fixed_version"] == "2.0.0"
        assert details["cvss_score"] == 9.8

    def test_cve_alert_has_enrichment(self):
        """Critical CVE alert should include risk details."""
        from agent_bom.alerts.scan_alerts import alerts_from_scan_result

        report = {
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-2025-0002",
                    "severity": "critical",
                    "is_kev": False,
                    "package": "risky-pkg",
                    "risk_score": 8.5,
                    "affected_agents": ["a", "b"],
                    "exposed_credentials": [],
                    "fixed_version": None,
                    "cvss_score": 9.0,
                    "epss_score": None,
                }
            ],
            "agents": [],
        }
        alerts = alerts_from_scan_result(report)
        assert len(alerts) == 1
        assert alerts[0]["details"]["risk_score"] == 8.5
        assert alerts[0]["details"]["affected_agents"] == ["a", "b"]


# ── Policy Conditions ────────────────────────────────────────────────────────


class TestPolicyNewConditions:
    def test_min_scorecard_score_triggers(self):
        """min_scorecard_score should trigger when package score is below threshold."""
        from agent_bom.policy import _rule_matches

        pkg = _make_package(scorecard_score=3.0)
        br = _make_blast_radius(pkg=pkg)
        rule = {"id": "low-scorecard", "min_scorecard_score": 5.0}
        assert _rule_matches(rule, br) is True

    def test_min_scorecard_score_does_not_trigger_above(self):
        """min_scorecard_score should NOT trigger when score is above threshold."""
        from agent_bom.policy import _rule_matches

        pkg = _make_package(scorecard_score=7.0)
        br = _make_blast_radius(pkg=pkg)
        rule = {"id": "low-scorecard", "min_scorecard_score": 5.0}
        assert _rule_matches(rule, br) is False

    def test_min_scorecard_score_no_data(self):
        """min_scorecard_score should NOT trigger when no scorecard data."""
        from agent_bom.policy import _rule_matches

        pkg = _make_package(scorecard_score=None)
        br = _make_blast_radius(pkg=pkg)
        rule = {"id": "low-scorecard", "min_scorecard_score": 5.0}
        assert _rule_matches(rule, br) is False

    def test_max_epss_score_triggers(self):
        """max_epss_score should trigger when EPSS is above threshold."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(epss_score=0.8)
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "high-epss", "max_epss_score": 0.5}
        assert _rule_matches(rule, br) is True

    def test_max_epss_score_does_not_trigger_below(self):
        """max_epss_score should NOT trigger when EPSS is below threshold."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(epss_score=0.2)
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "high-epss", "max_epss_score": 0.5}
        assert _rule_matches(rule, br) is False

    def test_max_epss_score_no_data(self):
        """max_epss_score should NOT trigger when no EPSS data."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(epss_score=None)
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "high-epss", "max_epss_score": 0.5}
        assert _rule_matches(rule, br) is False

    def test_has_kev_with_no_fix(self):
        """has_kev_with_no_fix should trigger for KEV vulns without fixes."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(is_kev=True, fixed_version=None)
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "kev-no-fix", "has_kev_with_no_fix": True}
        assert _rule_matches(rule, br) is True

    def test_has_kev_with_no_fix_false_when_fix_exists(self):
        """has_kev_with_no_fix should NOT trigger when fix is available."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(is_kev=True, fixed_version="2.0.0")
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "kev-no-fix", "has_kev_with_no_fix": True}
        assert _rule_matches(rule, br) is False

    def test_has_kev_with_no_fix_false_when_not_kev(self):
        """has_kev_with_no_fix should NOT trigger for non-KEV vulns."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(is_kev=False, fixed_version=None)
        br = _make_blast_radius(vuln=vuln)
        rule = {"id": "kev-no-fix", "has_kev_with_no_fix": True}
        assert _rule_matches(rule, br) is False

    def test_combined_conditions(self):
        """Multiple new conditions should AND together."""
        from agent_bom.policy import _rule_matches

        vuln = _make_vuln(epss_score=0.9, is_kev=True, fixed_version=None)
        pkg = _make_package(scorecard_score=2.0)
        br = _make_blast_radius(vuln=vuln, pkg=pkg)
        rule = {
            "id": "triple-threat",
            "min_scorecard_score": 4.0,
            "max_epss_score": 0.5,
            "has_kev_with_no_fix": True,
        }
        assert _rule_matches(rule, br) is True

    def test_evaluate_policy_with_new_conditions(self):
        """Full policy evaluation with new conditions should work."""
        from agent_bom.policy import evaluate_policy

        vuln = _make_vuln(epss_score=0.9)
        pkg = _make_package(scorecard_score=2.0)
        br = _make_blast_radius(vuln=vuln, pkg=pkg)
        policy = {
            "name": "enterprise-policy",
            "rules": [
                {
                    "id": "low-scorecard-high-epss",
                    "description": "Poorly maintained packages with high exploit probability",
                    "min_scorecard_score": 4.0,
                    "max_epss_score": 0.5,
                    "action": "fail",
                },
            ],
        }
        result = evaluate_policy(policy, [br])
        assert not result["passed"]
        assert len(result["failures"]) == 1
        assert result["failures"][0]["rule_id"] == "low-scorecard-high-epss"


# ── JSON Output Integration ──────────────────────────────────────────────────


class TestJSONOutputIntegration:
    def test_to_json_includes_posture_scorecard(self):
        """to_json should include posture_scorecard field."""
        from agent_bom.output import to_json

        report = _make_report()
        result = to_json(report)
        assert "posture_scorecard" in result
        assert "grade" in result["posture_scorecard"]
        assert "score" in result["posture_scorecard"]

    def test_to_json_includes_credential_ranking(self):
        """to_json should include credential_risk_ranking field."""
        from agent_bom.output import to_json

        report = _make_report()
        result = to_json(report)
        assert "credential_risk_ranking" in result
        assert isinstance(result["credential_risk_ranking"], list)

    def test_to_json_includes_incident_correlation(self):
        """to_json should include incident_correlation field."""
        from agent_bom.output import to_json

        report = _make_report()
        result = to_json(report)
        assert "incident_correlation" in result
        assert isinstance(result["incident_correlation"], list)

    def test_to_json_scorecard_with_vulns(self):
        """to_json scorecard should reflect vulnerability data."""
        from agent_bom.output import to_json

        vuln = _make_vuln(severity="CRITICAL")
        br = _make_blast_radius(vuln=vuln)
        report = _make_report(blast_radii=[br])
        result = to_json(report)
        sc = result["posture_scorecard"]
        assert sc["score"] < 100

    def test_to_json_includes_scorecard_summary(self):
        """to_json should include explicit Scorecard enrichment coverage."""
        from agent_bom.output import to_json

        pkg = _make_package()
        pkg.repository_url = "https://github.com/example/repo"
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        agent.mcp_servers[0].packages[0].scorecard_lookup_state = "failed"
        report = _make_report(agents=[agent])
        result = to_json(report)
        summary = result["scorecard_summary"]
        assert summary["eligible_packages"] == 1
        assert summary["failed_packages"] == 1

    def test_posture_supply_chain_detail_explains_scorecard_coverage_state(self):
        """Posture details should explain when Scorecard coverage is pending, not hide behind a neutral default."""
        from agent_bom.posture import compute_posture_scorecard

        pkg = _make_package()
        pkg.homepage = "https://github.com/example/repo"
        server = _make_server(packages=[pkg])
        agent = _make_agent(servers=[server])
        agent.mcp_servers[0].packages[0].scorecard_lookup_state = "failed"
        report = _make_report(agents=[agent])
        sc = compute_posture_scorecard(report)
        assert "coverage pending" in sc.dimensions["supply_chain_quality"].details.lower()

    def test_to_json_incident_with_agents(self):
        """to_json incidents should list agents with vulns."""
        from agent_bom.output import to_json

        agent = _make_agent()
        vuln = _make_vuln(severity="HIGH")
        br = _make_blast_radius(vuln=vuln, agents=[agent])
        report = _make_report(agents=[agent], blast_radii=[br])
        result = to_json(report)
        assert len(result["incident_correlation"]) == 1
        assert result["incident_correlation"][0]["agent_name"] == "test-agent"


# ── DimensionScore ───────────────────────────────────────────────────────────


class TestDimensionScore:
    def test_to_dict_weighted_score(self):
        """DimensionScore to_dict should compute weighted_score correctly."""
        from agent_bom.posture import DimensionScore

        ds = DimensionScore(name="Test", score=80.0, weight=0.25)
        d = ds.to_dict()
        assert d["weighted_score"] == 20.0

    def test_to_dict_fields(self):
        """DimensionScore to_dict should have all fields."""
        from agent_bom.posture import DimensionScore

        ds = DimensionScore(name="Test", score=50.0, weight=0.1, details="test detail")
        d = ds.to_dict()
        assert d["name"] == "Test"
        assert d["score"] == 50.0
        assert d["weight"] == 0.1
        assert d["details"] == "test detail"
