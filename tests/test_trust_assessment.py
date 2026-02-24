"""Tests for ClawHub-style trust assessment."""

from pathlib import Path
from unittest.mock import patch

from agent_bom.parsers.skill_audit import SkillAuditResult, SkillFinding, audit_skill_result
from agent_bom.parsers.skills import SkillMetadata, SkillScanResult
from agent_bom.parsers.trust_assessment import (
    Confidence,
    TrustAssessmentResult,
    TrustCategoryResult,
    TrustLevel,
    Verdict,
    _compute_verdict,
    _generate_recommendations,
    assess_trust,
)

# ── Helper: build a well-formed SKILL.md frontmatter ────────────────────────

_GOOD_FRONTMATTER = """\
name: test-tool
description: A test security scanner
version: 1.0.0
metadata:
  openclaw:
    requires:
      bins:
        - test-tool
      optional_bins:
        - docker
      env: []
    optional_env:
      - name: API_KEY
        purpose: "Rate limit increase"
        sent_only_to: "https://api.example.com"
        required: false
    homepage: https://github.com/example/test-tool
    source: https://github.com/example/test-tool
    license: MIT
    install:
      - kind: pip
        package: test-tool
      - kind: pipx
        package: test-tool
      - kind: uv
        package: test-tool
    file_reads:
      - "~/.config/test/config.json"
    file_reads_justification: |
      Reads the test config to discover servers.
    file_writes: []
    network_endpoints:
      - url: "https://api.example.com"
        purpose: "Vulnerability lookup"
        auth: false
    sensitive_data_handling:
      in_memory_only: true
      written_to_disk: false
    checksums:
      sigstore_signed: true
    telemetry: false
    persistence: false
    privilege_escalation: false
"""

_MINIMAL_FRONTMATTER = """\
name: minimal
description: Minimal tool
version: 0.1.0
"""


def _make_scan(
    frontmatter: str = _GOOD_FRONTMATTER,
    cred_vars: list[str] | None = None,
    source_files: list[str] | None = None,
) -> SkillScanResult:
    """Build a SkillScanResult with given frontmatter."""
    meta = SkillMetadata(
        raw_frontmatter=frontmatter,
        name=_extract_yaml(frontmatter, "name"),
        description=_extract_yaml(frontmatter, "description"),
        source=_extract_yaml(frontmatter, "source"),
        homepage=_extract_yaml(frontmatter, "homepage"),
        license=_extract_yaml(frontmatter, "license"),
    )
    # Extract bins and install methods from frontmatter
    import re
    bins_match = re.search(r"requires:\s*\n\s+bins:\s*\n((?:\s+-\s+\S+\n?)+)", frontmatter)
    if bins_match:
        meta.required_bins = re.findall(r"^\s+-\s+(.+)$", bins_match.group(1), re.MULTILINE)
    for kind in re.finditer(r"kind:\s*(\w+)", frontmatter):
        meta.install_methods.append(kind.group(1))

    return SkillScanResult(
        metadata=meta,
        credential_env_vars=cred_vars or [],
        source_files=source_files or ["SKILL.md"],
    )


def _extract_yaml(raw: str, key: str) -> str:
    """Extract a simple key: value from YAML-ish text."""
    import re
    m = re.search(rf"^\s*{key}:\s*(.+)$", raw, re.MULTILINE)
    return m.group(1).strip().strip("'\"") if m else ""


def _make_audit(**overrides) -> SkillAuditResult:
    """Build a SkillAuditResult with optional overrides."""
    defaults = {
        "findings": [],
        "packages_checked": 0,
        "servers_checked": 0,
        "credentials_checked": 0,
        "passed": True,
    }
    defaults.update(overrides)
    return SkillAuditResult(**defaults)


def _finding(category: str, severity: str = "high", title: str = "test") -> SkillFinding:
    """Build a minimal SkillFinding."""
    return SkillFinding(
        severity=severity,
        category=category,
        title=title,
        detail="test detail",
        source_file="SKILL.md",
    )


# ═══════════════════════════════════════════════════════════════════════════════
# 1. Data structure tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_trust_level_enum_values():
    """TrustLevel has pass/info/warn/fail."""
    assert TrustLevel.PASS.value == "pass"
    assert TrustLevel.INFO.value == "info"
    assert TrustLevel.WARN.value == "warn"
    assert TrustLevel.FAIL.value == "fail"


def test_verdict_enum_values():
    """Verdict has benign/suspicious/malicious."""
    assert Verdict.BENIGN.value == "benign"
    assert Verdict.SUSPICIOUS.value == "suspicious"
    assert Verdict.MALICIOUS.value == "malicious"


def test_confidence_enum_values():
    """Confidence has high/medium/low."""
    assert Confidence.HIGH.value == "high"
    assert Confidence.MEDIUM.value == "medium"
    assert Confidence.LOW.value == "low"


def test_trust_assessment_result_to_dict():
    """TrustAssessmentResult serializes correctly."""
    result = TrustAssessmentResult(
        categories=[
            TrustCategoryResult(
                name="Test", key="test", level=TrustLevel.PASS,
                summary="All good", details=["detail1"], evidence=["ev1"],
            )
        ],
        verdict=Verdict.BENIGN,
        confidence=Confidence.HIGH,
        recommendations=[],
        skill_name="test-tool",
        source_file="SKILL.md",
    )
    d = result.to_dict()
    assert d["verdict"] == "benign"
    assert d["confidence"] == "high"
    assert d["skill_name"] == "test-tool"
    assert len(d["categories"]) == 1
    assert d["categories"][0]["level"] == "pass"
    assert d["categories"][0]["key"] == "test"


def test_worst_level_property():
    """worst_level returns the most severe level across categories."""
    result = TrustAssessmentResult(
        categories=[
            TrustCategoryResult(name="A", key="a", level=TrustLevel.PASS, summary="ok"),
            TrustCategoryResult(name="B", key="b", level=TrustLevel.WARN, summary="warn"),
            TrustCategoryResult(name="C", key="c", level=TrustLevel.INFO, summary="info"),
        ],
    )
    assert result.worst_level == TrustLevel.WARN


# ═══════════════════════════════════════════════════════════════════════════════
# 2. Category assessment tests — Purpose & Capability
# ═══════════════════════════════════════════════════════════════════════════════


def test_purpose_capability_pass():
    """Full metadata → PASS."""
    scan = _make_scan()
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "purpose_capability")
    assert cat.level == TrustLevel.PASS


def test_purpose_capability_warn_no_name():
    """Missing name → WARN."""
    fm = "description: A tool\nversion: 1.0\n"
    scan = _make_scan(frontmatter=fm)
    scan.metadata.name = ""
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "purpose_capability")
    assert cat.level == TrustLevel.WARN


def test_purpose_capability_fail_shell_access():
    """Shell access findings → FAIL."""
    scan = _make_scan()
    audit = _make_audit(findings=[_finding("shell_access")])
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "purpose_capability")
    assert cat.level == TrustLevel.FAIL


# ═══════════════════════════════════════════════════════════════════════════════
# 3. Category assessment tests — Instruction Scope
# ═══════════════════════════════════════════════════════════════════════════════


def test_instruction_scope_pass():
    """file_reads + justification + data handling → PASS."""
    scan = _make_scan()
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "instruction_scope")
    assert cat.level == TrustLevel.PASS


def test_instruction_scope_warn_no_file_reads():
    """No file_reads → WARN."""
    fm = _MINIMAL_FRONTMATTER  # has name/description but no file_reads
    scan = _make_scan(frontmatter=fm)
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "instruction_scope")
    assert cat.level == TrustLevel.WARN


def test_instruction_scope_fail_credential_access():
    """Credential file access → FAIL."""
    scan = _make_scan()
    audit = _make_audit(findings=[_finding("credential_file_access", severity="critical")])
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "instruction_scope")
    assert cat.level == TrustLevel.FAIL


# ═══════════════════════════════════════════════════════════════════════════════
# 4. Category assessment tests — Install Mechanism
# ═══════════════════════════════════════════════════════════════════════════════


def test_install_mechanism_pass():
    """Multiple install methods + source + signing → PASS."""
    scan = _make_scan()
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "install_mechanism")
    assert cat.level == TrustLevel.PASS


def test_install_mechanism_warn_no_source():
    """No source URL → WARN."""
    fm = "name: test\ndescription: test\nversion: 1.0\nmetadata:\n  openclaw:\n    install:\n      - kind: pip\n        package: test\n"
    scan = _make_scan(frontmatter=fm)
    scan.metadata.source = ""
    scan.metadata.homepage = ""
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "install_mechanism")
    assert cat.level == TrustLevel.WARN


def test_install_mechanism_fail_no_install_no_source():
    """No install methods and no source → FAIL."""
    fm = "name: test\ndescription: test\nversion: 1.0\n"
    scan = _make_scan(frontmatter=fm)
    scan.metadata.source = ""
    scan.metadata.install_methods = []
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "install_mechanism")
    assert cat.level == TrustLevel.FAIL


# ═══════════════════════════════════════════════════════════════════════════════
# 5. Category assessment tests — Credentials
# ═══════════════════════════════════════════════════════════════════════════════


def test_credentials_pass_none():
    """No credentials → PASS."""
    scan = _make_scan(cred_vars=[])
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "credentials")
    assert cat.level == TrustLevel.PASS


def test_credentials_warn_excessive_undocumented():
    """Excessive credentials without documentation → WARN."""
    fm = "name: test\ndescription: test\nversion: 1.0\n"
    scan = _make_scan(frontmatter=fm, cred_vars=["KEY1", "KEY2", "KEY3"])
    audit = _make_audit(findings=[_finding("excessive_permissions", severity="medium")])
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "credentials")
    assert cat.level == TrustLevel.WARN


def test_credentials_fail_bypass_with_creds():
    """Safety bypass + credential access → FAIL."""
    scan = _make_scan(cred_vars=["SECRET_KEY"])
    audit = _make_audit(findings=[_finding("confirmation_bypass", severity="critical")])
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "credentials")
    assert cat.level == TrustLevel.FAIL


# ═══════════════════════════════════════════════════════════════════════════════
# 6. Category assessment tests — Persistence & Privilege
# ═══════════════════════════════════════════════════════════════════════════════


def test_persistence_privilege_pass():
    """All false → PASS."""
    scan = _make_scan()
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "persistence_privilege")
    assert cat.level == TrustLevel.PASS


def test_persistence_privilege_warn_no_metadata():
    """No frontmatter at all → WARN."""
    scan = SkillScanResult(
        metadata=SkillMetadata(raw_frontmatter=""),
        source_files=["CLAUDE.md"],
    )
    # Patch out the empty raw_frontmatter
    scan.metadata = SkillMetadata()  # no raw_frontmatter
    audit = _make_audit()
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "persistence_privilege")
    assert cat.level == TrustLevel.WARN


def test_persistence_privilege_fail_escalation():
    """Privilege escalation detected → FAIL."""
    scan = _make_scan()
    audit = _make_audit(findings=[_finding("privilege_escalation", severity="high")])
    result = assess_trust(scan, audit)
    cat = next(c for c in result.categories if c.key == "persistence_privilege")
    assert cat.level == TrustLevel.FAIL


# ═══════════════════════════════════════════════════════════════════════════════
# 7. Verdict computation tests
# ═══════════════════════════════════════════════════════════════════════════════


def _cats(*levels: TrustLevel) -> list[TrustCategoryResult]:
    """Build minimal categories with given levels."""
    return [
        TrustCategoryResult(name=f"Cat{i}", key=f"cat{i}", level=lv, summary="")
        for i, lv in enumerate(levels)
    ]


def test_verdict_all_pass_is_benign_high():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.PASS, TrustLevel.PASS,
    ))
    assert verdict == Verdict.BENIGN
    assert conf == Confidence.HIGH


def test_verdict_pass_plus_info_is_benign_medium():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.INFO, TrustLevel.INFO,
    ))
    assert verdict == Verdict.BENIGN
    assert conf == Confidence.MEDIUM


def test_verdict_one_warn_is_suspicious_low():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.PASS, TrustLevel.WARN,
    ))
    assert verdict == Verdict.SUSPICIOUS
    assert conf == Confidence.LOW


def test_verdict_three_warns_is_suspicious_medium():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.WARN,
        TrustLevel.WARN, TrustLevel.WARN,
    ))
    assert verdict == Verdict.SUSPICIOUS
    assert conf == Confidence.MEDIUM


def test_verdict_one_fail_is_suspicious_medium():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.PASS, TrustLevel.FAIL,
    ))
    assert verdict == Verdict.SUSPICIOUS
    assert conf == Confidence.MEDIUM


def test_verdict_two_fails_is_malicious_high():
    verdict, conf = _compute_verdict(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.FAIL, TrustLevel.FAIL,
    ))
    assert verdict == Verdict.MALICIOUS
    assert conf == Confidence.HIGH


# ═══════════════════════════════════════════════════════════════════════════════
# 8. Recommendation tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_no_recommendations_when_all_pass():
    recs = _generate_recommendations(_cats(
        TrustLevel.PASS, TrustLevel.PASS, TrustLevel.PASS,
        TrustLevel.PASS, TrustLevel.PASS,
    ))
    assert recs == []


def test_recommendations_for_warn():
    """WARN categories generate recommendations."""
    cats = [
        TrustCategoryResult(
            name="Install Mechanism", key="install_mechanism",
            level=TrustLevel.WARN, summary="No source",
        ),
    ]
    recs = _generate_recommendations(cats)
    assert len(recs) >= 1
    assert any("source" in r.lower() for r in recs)


def test_recommendations_for_fail():
    """FAIL categories generate recommendations."""
    cats = [
        TrustCategoryResult(
            name="Persistence & Privilege", key="persistence_privilege",
            level=TrustLevel.FAIL, summary="Privilege escalation",
        ),
    ]
    recs = _generate_recommendations(cats)
    assert len(recs) >= 1
    assert any("privilege" in r.lower() or "escalation" in r.lower() for r in recs)


# ═══════════════════════════════════════════════════════════════════════════════
# 9. Integration tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_assess_trust_end_to_end():
    """Full pipeline: parse → audit → assess for a well-formed skill."""
    scan = _make_scan()
    audit = _make_audit()
    result = assess_trust(scan, audit)

    assert len(result.categories) == 5
    assert result.verdict == Verdict.BENIGN
    assert result.confidence == Confidence.HIGH
    assert result.skill_name == "test-tool"
    assert result.source_file == "SKILL.md"

    # All 5 categories should be PASS for the well-formed frontmatter
    for cat in result.categories:
        assert cat.level == TrustLevel.PASS, f"{cat.name} expected PASS, got {cat.level}"


def test_assess_trust_no_frontmatter():
    """Gracefully handles scan result with no metadata."""
    scan = SkillScanResult(
        metadata=None,
        source_files=["CLAUDE.md"],
    )
    audit = _make_audit()
    result = assess_trust(scan, audit)

    assert len(result.categories) == 5
    # Without metadata, most categories should be WARN or INFO
    assert result.verdict in (Verdict.SUSPICIOUS, Verdict.MALICIOUS)


def test_assess_trust_agent_bom_skill():
    """Our own SKILL.md should score benign."""
    skill_path = Path(__file__).parent.parent / "integrations" / "openclaw" / "SKILL.md"
    if not skill_path.exists():
        return  # Skip if not in the repo

    from agent_bom.parsers.skills import parse_skill_file

    scan = parse_skill_file(skill_path)
    with patch("agent_bom.parsers.skill_audit._batch_verify_packages_sync",
               return_value={}):
        audit = audit_skill_result(scan)
    result = assess_trust(scan, audit)

    assert result.verdict == Verdict.BENIGN
    assert result.confidence in (Confidence.HIGH, Confidence.MEDIUM)


def test_trust_assessment_in_json_output():
    """trust_assessment appears in JSON output when set."""
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    report = AIBOMReport()
    report.trust_assessment_data = {
        "verdict": "benign",
        "confidence": "high",
        "categories": [],
    }
    data = to_json(report)
    assert "trust_assessment" in data
    assert data["trust_assessment"]["verdict"] == "benign"


def test_trust_assessment_absent_when_no_skill():
    """trust_assessment not in JSON when no skill files scanned."""
    from agent_bom.models import AIBOMReport
    from agent_bom.output import to_json

    report = AIBOMReport()
    data = to_json(report)
    assert "trust_assessment" not in data


# ═══════════════════════════════════════════════════════════════════════════════
# 10. MCP tool tests
# ═══════════════════════════════════════════════════════════════════════════════


def test_mcp_skill_trust_tool_exists():
    """skill_trust tool is registered on the MCP server."""
    from agent_bom.mcp_server import _SERVER_CARD_TOOLS

    tool_names = [t["name"] for t in _SERVER_CARD_TOOLS]
    assert "skill_trust" in tool_names


def test_mcp_server_card_has_9_tools():
    """Server card lists 9 tools."""
    from agent_bom.mcp_server import _SERVER_CARD_TOOLS

    assert len(_SERVER_CARD_TOOLS) == 9
