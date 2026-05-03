"""Canonical compliance framework coverage metadata."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from agent_bom.atlas import ATLAS_TECHNIQUES
from agent_bom.cis_controls import CIS_CONTROLS
from agent_bom.cloud.aisvs_benchmark import AISVS_CHECK_IDS
from agent_bom.cmmc import CMMC_PRACTICES
from agent_bom.eu_ai_act import EU_AI_ACT
from agent_bom.fedramp import FEDRAMP_MODERATE
from agent_bom.iso_27001 import ISO_27001
from agent_bom.nist_800_53 import NIST_800_53
from agent_bom.nist_ai_rmf import NIST_AI_RMF
from agent_bom.nist_csf import NIST_CSF
from agent_bom.owasp import OWASP_LLM_TOP10
from agent_bom.owasp_agentic import OWASP_AGENTIC_TOP10
from agent_bom.owasp_mcp import OWASP_MCP_TOP10
from agent_bom.pci_dss import PCI_DSS_REQUIREMENTS
from agent_bom.soc2 import SOC2_TSC


@dataclass(frozen=True)
class ComplianceFrameworkMetadata:
    """Metadata shared by compliance APIs and docs coverage disclosures."""

    family: str
    framework: str
    slug: str
    output_key: str
    summary_prefix: str
    tag_field: str
    catalog: Mapping[str, str]
    report_label: str
    bundled_unit: str
    source_standard_size: str
    coverage: str
    full_catalog_size: int | None = None

    @property
    def control_count(self) -> int:
        return len(self.catalog)

    @property
    def bundled_controls_label(self) -> str:
        if self.full_catalog_size is not None:
            return f"{self.control_count} / {self.full_catalog_size}"
        return f"{self.control_count} {self.bundled_unit}"


@dataclass(frozen=True)
class ComplianceBenchmarkMetadata:
    """Metadata for benchmark-style compliance surfaces."""

    family: str
    framework: str
    slug: str
    check_ids: tuple[str, ...]
    source_standard_size: str
    coverage: str

    @property
    def check_count(self) -> int:
        return len(self.check_ids)

    @property
    def bundled_controls_label(self) -> str:
        return f"{self.check_count} checks"


TAG_MAPPED_FRAMEWORKS: tuple[ComplianceFrameworkMetadata, ...] = (
    ComplianceFrameworkMetadata(
        family="OWASP",
        framework="LLM Top 10 (2025)",
        slug="owasp-llm",
        output_key="owasp_llm_top10",
        summary_prefix="owasp",
        tag_field="owasp_tags",
        catalog=OWASP_LLM_TOP10,
        report_label="OWASP LLM Top 10",
        bundled_unit="controls",
        source_standard_size="10",
        coverage="Full Top-10",
        full_catalog_size=10,
    ),
    ComplianceFrameworkMetadata(
        family="OWASP",
        framework="MCP Top 10 (2025)",
        slug="owasp-mcp",
        output_key="owasp_mcp_top10",
        summary_prefix="owasp_mcp",
        tag_field="owasp_mcp_tags",
        catalog=OWASP_MCP_TOP10,
        report_label="OWASP MCP Top 10",
        bundled_unit="controls",
        source_standard_size="10",
        coverage="Full Top-10",
        full_catalog_size=10,
    ),
    ComplianceFrameworkMetadata(
        family="OWASP",
        framework="Agentic Top 10 (2026)",
        slug="owasp-agentic",
        output_key="owasp_agentic_top10",
        summary_prefix="owasp_agentic",
        tag_field="owasp_agentic_tags",
        catalog=OWASP_AGENTIC_TOP10,
        report_label="OWASP Agentic Top 10",
        bundled_unit="controls",
        source_standard_size="10",
        coverage="Full Top-10",
        full_catalog_size=10,
    ),
    ComplianceFrameworkMetadata(
        family="NIST / FedRAMP",
        framework="AI RMF 1.0",
        slug="nist",
        output_key="nist_ai_rmf",
        summary_prefix="nist",
        tag_field="nist_ai_rmf_tags",
        catalog=NIST_AI_RMF,
        report_label="NIST AI RMF",
        bundled_unit="subcategories",
        source_standard_size="~70",
        coverage="Govern / Map / Measure / Manage controls relevant to AI supply chain + MCP",
    ),
    ComplianceFrameworkMetadata(
        family="NIST / FedRAMP",
        framework="CSF 2.0",
        slug="nist-csf",
        output_key="nist_csf",
        summary_prefix="nist_csf",
        tag_field="nist_csf_tags",
        catalog=NIST_CSF,
        report_label="NIST CSF",
        bundled_unit="categories",
        source_standard_size="~108",
        coverage="Supply-chain, identity, asset, monitoring categories",
    ),
    ComplianceFrameworkMetadata(
        family="NIST / FedRAMP",
        framework="800-53 Rev 5",
        slug="nist-800-53",
        output_key="nist_800_53",
        summary_prefix="nist_800_53",
        tag_field="nist_800_53_tags",
        catalog=NIST_800_53,
        report_label="NIST 800-53",
        bundled_unit="controls",
        source_standard_size="~1,006",
        coverage="Vulnerability-driven mapping (RA-5, SI-2, etc.); not a complete catalog",
    ),
    ComplianceFrameworkMetadata(
        family="NIST / FedRAMP",
        framework="FedRAMP Moderate",
        slug="fedramp",
        output_key="fedramp",
        summary_prefix="fedramp",
        tag_field="fedramp_tags",
        catalog={control: control for control in sorted(FEDRAMP_MODERATE)},
        report_label="FedRAMP",
        bundled_unit="controls",
        source_standard_size="~325",
        coverage="Subset of 800-53 controls in the Moderate baseline",
    ),
    ComplianceFrameworkMetadata(
        family="MITRE",
        framework="ATLAS",
        slug="atlas",
        output_key="mitre_atlas",
        summary_prefix="atlas",
        tag_field="atlas_tags",
        catalog=ATLAS_TECHNIQUES,
        report_label="MITRE ATLAS",
        bundled_unit="techniques",
        source_standard_size="~90",
        coverage="LLM/AI techniques: prompt injection, jailbreak, supply-chain, exfiltration, agent tool abuse",
    ),
    ComplianceFrameworkMetadata(
        family="MITRE",
        framework="ATT&CK Enterprise",
        slug="attack",
        output_key="mitre_attack",
        summary_prefix="attack",
        tag_field="attack_tags",
        catalog={},
        report_label="MITRE ATT&CK",
        bundled_unit="techniques",
        source_standard_size="~600",
        coverage="Adversary techniques tagged via CWE → CAPEC → ATT&CK on every blast-radius finding",
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="EU AI Act",
        slug="eu-ai-act",
        output_key="eu_ai_act",
        summary_prefix="eu_ai_act",
        tag_field="eu_ai_act_tags",
        catalog=EU_AI_ACT,
        report_label="EU AI Act",
        bundled_unit="articles",
        source_standard_size="~113",
        coverage=(
            "Articles 5/6/9/10/15/17 (prohibited practices, high-risk classification, risk mgmt, "
            "data governance, accuracy/cybersecurity, QMS)"
        ),
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="ISO/IEC 27001:2022",
        slug="iso-27001",
        output_key="iso_27001",
        summary_prefix="iso_27001",
        tag_field="iso_27001_tags",
        catalog=ISO_27001,
        report_label="ISO 27001",
        bundled_unit="Annex A controls",
        source_standard_size="93",
        coverage="Supplier, vulnerability, cryptography, secure-dev, evidence collection",
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="SOC 2 TSC",
        slug="soc2",
        output_key="soc2",
        summary_prefix="soc2",
        tag_field="soc2_tags",
        catalog=SOC2_TSC,
        report_label="SOC 2",
        bundled_unit="criteria",
        source_standard_size="~64",
        coverage="Common Criteria 6.x / 7.x / 8.x / 9.x (access, monitoring, change mgmt, vendor risk)",
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="CIS Controls v8",
        slug="cis",
        output_key="cis_controls",
        summary_prefix="cis",
        tag_field="cis_tags",
        catalog=CIS_CONTROLS,
        report_label="CIS Controls",
        bundled_unit="safeguards",
        source_standard_size="153",
        coverage="Software inventory, vulnerability mgmt, secure-dev (CIS 02 / 07 / 16)",
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="CMMC 2.0 Level 2",
        slug="cmmc",
        output_key="cmmc",
        summary_prefix="cmmc",
        tag_field="cmmc_tags",
        catalog=CMMC_PRACTICES,
        report_label="CMMC",
        bundled_unit="practices",
        source_standard_size="110",
        coverage="RA / SI / SC / CM / AC / IA practices most relevant to vulnerable-package risk",
    ),
    ComplianceFrameworkMetadata(
        family="Regulatory",
        framework="PCI DSS v4.0",
        slug="pci-dss",
        output_key="pci_dss",
        summary_prefix="pci_dss",
        tag_field="pci_dss_tags",
        catalog=PCI_DSS_REQUIREMENTS,
        report_label="PCI DSS",
        bundled_unit="requirements",
        source_standard_size="12",
        coverage="Requirements 2/3/4/5/6/7/8/10/11/12 for vulnerable-package and evidence risk",
    ),
)

AISVS_BENCHMARK = ComplianceBenchmarkMetadata(
    family="OWASP",
    framework="AISVS v1.0",
    slug="aisvs",
    check_ids=AISVS_CHECK_IDS,
    source_standard_size="~50 verification reqs",
    coverage="Programmatically verifiable subset (AI-4/5/6/7/8 categories)",
)


def framework_output_key_by_slug() -> dict[str, str]:
    """Return API output keys keyed by public framework slug."""

    return {metadata.slug: metadata.output_key for metadata in TAG_MAPPED_FRAMEWORKS}


def framework_report_labels_by_slug() -> dict[str, tuple[str, str]]:
    """Return API output keys and report labels keyed by public framework slug."""

    return {metadata.slug: (metadata.output_key, metadata.report_label) for metadata in TAG_MAPPED_FRAMEWORKS}


def render_compliance_coverage_table() -> str:
    """Render the committed architecture coverage table from metadata."""

    lines = [
        "| Family | Framework | Bundled controls | Source-standard size (approx.) | What's covered |",
        "|---|---|---|---|---|",
    ]
    rows = [
        *(
            (
                metadata.family,
                metadata.framework,
                metadata.bundled_controls_label,
                metadata.source_standard_size,
                metadata.coverage,
            )
            for metadata in TAG_MAPPED_FRAMEWORKS[:3]
        ),
        (
            AISVS_BENCHMARK.family,
            AISVS_BENCHMARK.framework,
            AISVS_BENCHMARK.bundled_controls_label,
            AISVS_BENCHMARK.source_standard_size,
            AISVS_BENCHMARK.coverage,
        ),
        *(
            (
                metadata.family,
                metadata.framework,
                metadata.bundled_controls_label,
                metadata.source_standard_size,
                metadata.coverage,
            )
            for metadata in TAG_MAPPED_FRAMEWORKS[3:]
        ),
    ]
    lines.extend(
        f"| {family} | {framework} | {bundled} | {source_size} | {coverage} |" for family, framework, bundled, source_size, coverage in rows
    )
    return "\n".join(lines)
