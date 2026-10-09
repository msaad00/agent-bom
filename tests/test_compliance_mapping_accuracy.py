"""Pin framework catalogs to their official identifiers and tagging semantics.

Each tagging rule is asserted against the meaning of the control it emits,
not merely against the current output, so a renumbering or a drifted rule
fails here before it reaches a report.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_bom.constants import CWE_COMPLIANCE_MAP
from agent_bom.eu_ai_act import EU_AI_ACT
from agent_bom.eu_ai_act import tag_blast_radius as tag_eu_ai_act
from agent_bom.evidence.control_modes import is_detective_control
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, MCPTool, Package, Severity, Vulnerability
from agent_bom.owasp import OWASP_LLM_TOP10
from agent_bom.owasp import tag_blast_radius as tag_owasp
from agent_bom.soc2 import SOC2_TSC
from agent_bom.soc2 import tag_blast_radius as tag_soc2
from agent_bom.vuln_compliance import tag_vulnerability

_REPO_ROOT = Path(__file__).resolve().parents[1]

# OWASP Top 10 for LLM Applications 2025 (genai.owasp.org/llm-top-10/).
OFFICIAL_OWASP_LLM_2025 = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

SUPPLY_CHAIN = "LLM03"
SENSITIVE_INFO = "LLM02"
POISONING = "LLM04"
OUTPUT_HANDLING = "LLM05"
EXCESSIVE_AGENCY = "LLM06"
SYSTEM_PROMPT_LEAKAGE = "LLM07"
VECTOR_EMBEDDING = "LLM08"


def _br(
    *,
    pkg: str = "flask",
    severity: Severity = Severity.MEDIUM,
    tools: list[MCPTool] | None = None,
    creds: list[str] | None = None,
    cwes: list[str] | None = None,
    fixed: str | None = None,
    kev: bool = False,
    malicious: bool = False,
) -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2025-0001",
        summary="test",
        severity=severity,
        fixed_version=fixed,
        cwe_ids=cwes or [],
        is_kev=kev,
    )
    package = Package(name=pkg, version="1.0.0", ecosystem="pypi", is_malicious=malicious)
    return BlastRadius(
        vulnerability=vuln,
        package=package,
        affected_servers=[MCPServer(name="srv")],
        affected_agents=[Agent(name="a", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp")],
        exposed_credentials=creds or [],
        exposed_tools=tools or [],
    )


_EXEC_TOOL = MCPTool(name="run_shell", description="execute a shell command")
_READ_TOOL = MCPTool(name="read_file", description="read a file from disk")


def _ui_catalog(name: str) -> dict[str, str]:
    source = (_REPO_ROOT / "ui" / "lib" / "api.ts").read_text(encoding="utf-8")
    match = re.search(rf"export const {name}: Record<string, string> = \{{(.*?)\n\}};", source, re.S)
    assert match, f"{name} not found in ui/lib/api.ts"
    return dict(re.findall(r'^\s*"?([A-Za-z0-9.\-]+)"?:\s*"([^"]+)",\s*$', match.group(1), re.M))


# ─── OWASP LLM Top 10 (2025) ──────────────────────────────────────────────────


def test_owasp_llm_catalog_is_the_official_2025_list() -> None:
    assert OWASP_LLM_TOP10 == OFFICIAL_OWASP_LLM_2025


def test_ui_owasp_llm_catalog_matches_backend() -> None:
    assert _ui_catalog("OWASP_LLM_TOP10") == OFFICIAL_OWASP_LLM_2025


def test_vulnerable_dependency_is_supply_chain_not_output_handling() -> None:
    tags = tag_owasp(_br())
    assert SUPPLY_CHAIN in tags
    assert OUTPUT_HANDLING not in tags


def test_exposed_credentials_are_sensitive_information_disclosure() -> None:
    assert SENSITIVE_INFO in tag_owasp(_br(creds=["API_KEY"]))
    assert SENSITIVE_INFO not in tag_owasp(_br())


def test_execute_tool_is_improper_output_handling() -> None:
    assert OUTPUT_HANDLING in tag_owasp(_br(tools=[_EXEC_TOOL]))


def test_read_tool_is_not_system_prompt_leakage() -> None:
    tags = tag_owasp(_br(tools=[_READ_TOOL]))
    assert SYSTEM_PROMPT_LEAKAGE not in tags
    assert SENSITIVE_INFO in tags


def test_many_tools_with_high_cve_is_excessive_agency() -> None:
    tools = [MCPTool(name=f"t{i}", description="list items") for i in range(6)]
    assert EXCESSIVE_AGENCY in tag_owasp(_br(tools=tools, severity=Severity.HIGH))
    assert EXCESSIVE_AGENCY not in tag_owasp(_br(tools=tools, severity=Severity.LOW))


def test_training_data_package_is_data_and_model_poisoning_once() -> None:
    tags = tag_owasp(_br(pkg="datasets", severity=Severity.HIGH))
    assert POISONING in tags
    assert tags.count(POISONING) == 1


def test_ai_framework_cve_alone_is_not_poisoning() -> None:
    assert POISONING not in tag_owasp(_br(pkg="langchain", severity=Severity.CRITICAL))


def test_vector_store_package_is_vector_and_embedding_weakness() -> None:
    assert VECTOR_EMBEDDING in tag_owasp(_br(pkg="chromadb"))
    assert VECTOR_EMBEDDING not in tag_owasp(_br(pkg="flask"))


def test_vuln_compliance_uses_the_same_2025_semantics() -> None:
    vuln = Vulnerability(id="CVE-2025-0002", summary="x", severity=Severity.HIGH)
    tags = tag_vulnerability(vuln, Package(name="langchain", version="1", ecosystem="pypi"))["owasp_llm"]
    assert SUPPLY_CHAIN in tags and POISONING not in tags
    tags = tag_vulnerability(vuln, Package(name="datasets", version="1", ecosystem="pypi"))["owasp_llm"]
    assert POISONING in tags
    tags = tag_vulnerability(vuln, Package(name="qdrant-client", version="1", ecosystem="pypi"))["owasp_llm"]
    assert VECTOR_EMBEDDING in tags


@pytest.mark.parametrize(
    ("cwe", "expected"),
    [
        ("CWE-78", OUTPUT_HANDLING),
        ("CWE-79", OUTPUT_HANDLING),
        ("CWE-89", OUTPUT_HANDLING),
        ("CWE-94", OUTPUT_HANDLING),
        ("CWE-200", SENSITIVE_INFO),
        ("CWE-798", SENSITIVE_INFO),
        ("CWE-269", EXCESSIVE_AGENCY),
        ("CWE-829", SUPPLY_CHAIN),
        ("CWE-400", "LLM10"),
    ],
)
def test_cwe_rows_use_2025_ids(cwe: str, expected: str) -> None:
    assert CWE_COMPLIANCE_MAP[cwe]["owasp_llm"] == [expected]


@pytest.mark.parametrize("cwe", ["CWE-287", "CWE-639", "CWE-444", "CWE-942"])
def test_access_control_and_transport_cwes_are_not_output_handling(cwe: str) -> None:
    assert "owasp_llm" not in CWE_COMPLIANCE_MAP[cwe]


def test_every_emitted_owasp_llm_code_is_in_the_catalog() -> None:
    from agent_bom.demo_estate import enterprise_risk
    from agent_bom.red_team_governance import _CATEGORY_FRAMEWORKS

    emitted: set[str] = set()
    for row in CWE_COMPLIANCE_MAP.values():
        emitted.update(row.get("owasp_llm", []))
    for rule in (*enterprise_risk._TOOL_RULES, *enterprise_risk._AI_RULES):
        emitted.update(rule.owasp)
    for refs in _CATEGORY_FRAMEWORKS.values():
        emitted.update(ref.removeprefix("OWASP-") for ref in refs if ref.startswith("OWASP-LLM"))
    assert emitted <= set(OFFICIAL_OWASP_LLM_2025)


def test_mcp_tool_rules_use_2025_semantics() -> None:
    from agent_bom.mcp_tool_rules import evaluate_tool

    def tags_for(name: str, prop: str, description: str = "A sufficiently descriptive tool description.") -> dict[str, set[str]]:
        tool = MCPTool(name=name, description=description, input_schema={"type": "object", "properties": {prop: {"type": "string"}}})
        return {f.rule_id: set(f.owasp_tags) for f in evaluate_tool(tool)}

    shell = tags_for("runner", "command")
    assert shell["MCP-TOOL-01-shell-input"] == {OUTPUT_HANDLING, EXCESSIVE_AGENCY}
    creds = tags_for("login", "api_key")
    assert creds["MCP-TOOL-05-credential-in-input"] == {SENSITIVE_INFO}
    weak = tags_for("thing", "name", description="")
    assert weak["MCP-TOOL-07-weak-description"] == {EXCESSIVE_AGENCY}


def test_red_team_categories_use_2025_ids() -> None:
    from agent_bom.red_team_governance import _CATEGORY_FRAMEWORKS

    assert "OWASP-LLM06" in _CATEGORY_FRAMEWORKS["tool_abuse"]
    assert "OWASP-LLM02" in _CATEGORY_FRAMEWORKS["data_exfiltration"]
    assert "OWASP-LLM02" in _CATEGORY_FRAMEWORKS["credential_leak"]
    assert "OWASP-LLM05" in _CATEGORY_FRAMEWORKS["response_manipulation"]


def test_dataset_card_tags_use_2025_poisoning_id() -> None:
    from agent_bom.parsers import compliance_tags

    source = Path(compliance_tags.__file__).read_text(encoding="utf-8")
    assert "LLM03 Training Data Poisoning" not in source
    assert "LLM04 Data and Model Poisoning" in source


# ─── EU AI Act ────────────────────────────────────────────────────────────────


def test_eu_ai_act_catalog_has_no_classification_articles() -> None:
    assert "ART-5" not in EU_AI_ACT
    assert "ART-6" not in EU_AI_ACT
    assert EU_AI_ACT == {
        "ART-9": "Risk Management System",
        "ART-10": "Data and Data Governance",
        "ART-12": "Record-Keeping",
        "ART-14": "Human Oversight",
        "ART-15": "Accuracy, Robustness and Cybersecurity",
        "ART-17": "Quality Management System",
    }


def test_ui_eu_ai_act_catalog_matches_backend() -> None:
    assert _ui_catalog("EU_AI_ACT") == EU_AI_ACT


def test_eu_ai_act_never_infers_prohibited_or_high_risk_status() -> None:
    worst = _br(pkg="langchain", severity=Severity.CRITICAL, creds=["SECRET"], tools=[_EXEC_TOOL, _READ_TOOL])
    tags = tag_eu_ai_act(worst)
    assert "ART-5" not in tags
    assert "ART-6" not in tags
    vuln = Vulnerability(id="CVE-2025-0003", summary="x", severity=Severity.CRITICAL)
    eu = tag_vulnerability(vuln, Package(name="langchain", version="1", ecosystem="pypi"))["eu_ai_act"]
    assert "ART-5" not in eu and "ART-6" not in eu


def test_eu_ai_act_cybersecurity_findings_land_on_art15() -> None:
    assert "ART-15" in tag_eu_ai_act(_br())
    assert "ART-15" in tag_eu_ai_act(_br(creds=["API_KEY"]))


def test_eu_ai_act_read_tools_and_creds_are_not_data_governance() -> None:
    assert "ART-10" not in tag_eu_ai_act(_br(creds=["DB_TOKEN"], tools=[_READ_TOOL]))


def test_eu_ai_act_execute_tools_are_human_oversight() -> None:
    assert "ART-14" in tag_eu_ai_act(_br(tools=[_EXEC_TOOL]))
    assert "ART-14" not in tag_eu_ai_act(_br(tools=[_READ_TOOL]))


def test_eu_ai_act_log_integrity_weakness_is_record_keeping() -> None:
    assert "ART-12" in tag_eu_ai_act(_br(cwes=["CWE-117"]))
    assert "ART-12" not in tag_eu_ai_act(_br(cwes=["CWE-79"]))


# ─── SOC 2 ────────────────────────────────────────────────────────────────────


def test_soc2_cc7_labels_match_the_criteria() -> None:
    assert "vulnerabilit" in SOC2_TSC["CC7.1"].lower()
    assert "anomal" not in SOC2_TSC["CC7.1"].lower()
    assert "anomal" in SOC2_TSC["CC7.2"].lower()
    assert "malicious" in SOC2_TSC["CC6.8"].lower()


def test_ui_soc2_catalog_matches_backend() -> None:
    assert _ui_catalog("SOC2_TSC") == SOC2_TSC


def test_soc2_cc71_is_evidenced_by_the_scan_not_failed_by_findings() -> None:
    assert is_detective_control("soc2_tags", "CC7.1")
    assert "CC7.1" not in tag_soc2(_br(severity=Severity.CRITICAL, kev=True))
    vuln = Vulnerability(id="CVE-2025-0004", summary="x", severity=Severity.HIGH)
    assert "CC7.1" not in tag_vulnerability(vuln, Package(name="flask", version="1", ecosystem="pypi"))["soc2"]


def test_soc2_dependency_cve_does_not_claim_anomaly_monitoring() -> None:
    assert "CC7.2" not in tag_soc2(_br(pkg="langchain"))


def test_soc2_malicious_software_criterion_needs_a_malicious_package() -> None:
    assert "CC6.8" not in tag_soc2(_br(severity=Severity.CRITICAL))
    assert "CC6.8" in tag_soc2(_br(malicious=True))
    vuln = Vulnerability(id="CVE-2025-0005", summary="x", severity=Severity.CRITICAL)
    assert "CC6.8" not in tag_vulnerability(vuln, Package(name="flask", version="1", ecosystem="pypi"))["soc2"]


# ─── Other catalogs: identifiers whose meaning was mislabeled ─────────────────


def test_nist_ai_rmf_ids_carry_their_official_meaning() -> None:
    from agent_bom.nist_ai_rmf import NIST_AI_RMF

    # GOVERN 1.7 is decommissioning, MAP 1.6 requirements elicitation, MAP 5.2
    # AI-actor engagement, MEASURE 2.5 validity, MEASURE 2.9 explainability,
    # MANAGE 2.2 sustaining value, MANAGE 2.4 deactivation — none of which the
    # tagger evidences.
    for wrong in ("GOVERN-1.7", "MAP-1.6", "MAP-5.2", "MEASURE-2.5", "MEASURE-2.9", "MANAGE-2.2", "MANAGE-2.4"):
        assert wrong not in NIST_AI_RMF, wrong
    assert "third-party" in NIST_AI_RMF["GOVERN-6.1"].lower()
    assert "human oversight" in NIST_AI_RMF["MAP-3.5"].lower()
    assert "third-party" in NIST_AI_RMF["MAP-4.1"].lower()
    assert "security" in NIST_AI_RMF["MEASURE-2.7"].lower()
    assert "safety" in NIST_AI_RMF["MEASURE-2.6"].lower()


def test_nist_ai_rmf_rules_use_the_matching_subcategory() -> None:
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.nist_ai_rmf import tag_blast_radius as tag_rmf

    base = tag_rmf(_br(severity=Severity.HIGH))
    assert {"GOVERN-6.1", "MAP-4.1"} <= set(base)
    assert "MAP-3.5" in tag_rmf(_br(tools=[_EXEC_TOOL]))
    assert "MEASURE-2.7" in tag_rmf(_br(pkg="langchain", severity=Severity.HIGH))
    assert "MANAGE-1.3" in tag_rmf(_br(fixed="2.0.0"))
    worst = tag_rmf(_br(pkg="langchain", severity=Severity.CRITICAL, creds=["K"], tools=[_EXEC_TOOL, _READ_TOOL], fixed="2", kev=True))
    assert set(worst) <= set(NIST_AI_RMF)
    vuln = Vulnerability(id="CVE-2025-0006", summary="x", severity=Severity.HIGH, fixed_version="2", is_kev=True)
    rmf = tag_vulnerability(vuln, Package(name="langchain", version="1", ecosystem="pypi"))["nist_ai_rmf"]
    assert set(rmf) <= set(NIST_AI_RMF)


def test_ui_nist_ai_rmf_catalog_matches_backend() -> None:
    from agent_bom.nist_ai_rmf import NIST_AI_RMF

    assert _ui_catalog("NIST_AI_RMF") == NIST_AI_RMF


def test_dataset_card_rmf_tags_are_in_catalog() -> None:
    from agent_bom.nist_ai_rmf import NIST_AI_RMF
    from agent_bom.parsers import compliance_tags

    source = Path(compliance_tags.__file__).read_text(encoding="utf-8")
    emitted = set(re.findall(r'"((?:GOVERN|MAP|MEASURE|MANAGE)-\d+\.\d+)', source))
    assert emitted and emitted <= set(NIST_AI_RMF)


def test_cis_safeguard_ids_match_v8() -> None:
    from agent_bom.cis_controls import CIS_CONTROLS

    assert "CIS-02.7" not in CIS_CONTROLS  # 2.7 allowlists scripts, not libraries
    assert "librar" in CIS_CONTROLS["CIS-02.6"].lower()
    assert "CIS-16.11" not in CIS_CONTROLS  # 16.11 is vetted security modules
    assert "harden" in CIS_CONTROLS["CIS-16.7"].lower()
    for row in CWE_COMPLIANCE_MAP.values():
        assert set(row.get("cis", [])) <= set(CIS_CONTROLS)


def test_nist_csf_containment_is_rs_mi_01() -> None:
    from agent_bom.nist_csf import NIST_CSF
    from agent_bom.nist_csf import tag_blast_radius as tag_csf

    assert "RS.MI-02" not in NIST_CSF
    assert "contained" in NIST_CSF["RS.MI-01"].lower()
    assert "RS.MI-01" in tag_csf(_br(kev=True))
    assert "adverse events" in NIST_CSF["DE.CM-09"].lower()


def test_owasp_agentic_titles_match_the_2026_list() -> None:
    from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10

    assert OWASP_AGENTIC_TOP10["ASI01"] == "Agent Goal Hijack"
    assert OWASP_AGENTIC_TOP10["ASI08"] == "Cascading Failures"
    assert OWASP_AGENTIC_TOP10["ASI10"] == "Rogue Agents"
    assert _ui_catalog("OWASP_AGENTIC_TOP10") == OWASP_AGENTIC_TOP10


def test_dependency_cve_does_not_claim_goal_hijack_or_trust_exploitation() -> None:
    from agent_bom.owasp_agentic import tag_blast_radius as tag_agentic

    tags = tag_agentic(_br(pkg="langchain", severity=Severity.CRITICAL, kev=True))
    assert "ASI04" in tags
    assert "ASI01" not in tags
    assert "ASI09" not in tags
    vuln = Vulnerability(id="CVE-2025-0007", summary="x", severity=Severity.CRITICAL, is_kev=True)
    agentic = tag_vulnerability(vuln, Package(name="langchain", version="1", ecosystem="pypi"))["owasp_agentic"]
    assert "ASI01" not in agentic and "ASI09" not in agentic
