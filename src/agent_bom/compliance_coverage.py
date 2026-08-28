"""Canonical compliance framework coverage metadata."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass

from agent_bom.atlas import ATLAS_TECHNIQUES
from agent_bom.cis_controls import CIS_CONTROLS
from agent_bom.cloud.aisvs_benchmark import AISVS_CHECK_IDS
from agent_bom.cmmc import CMMC_PRACTICES
from agent_bom.eu_ai_act import EU_AI_ACT
from agent_bom.fedramp import FEDRAMP_MODERATE
from agent_bom.iso_27001 import ISO_27001
from agent_bom.mitre_attack import get_bundled_attack_techniques
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
    scored: bool = True
    """Whether this framework contributes pass/warning/fail to the compliance score.

    ``False`` marks an APPLICABILITY OVERLAY: its entries are not controls an
    estate can pass or fail, they are techniques a finding makes *applicable*.
    Overlay entries carry ``applicable`` / ``not_applicable`` statuses and are
    excluded from ``overall_score`` / ``overall_status`` on every surface.
    """

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
        coverage="Applicability overlay (not scored): risks evidenced by observed AI/LLM findings",
        full_catalog_size=10,
        scored=False,
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
        coverage="Applicability overlay (not scored): risks evidenced by observed MCP findings",
        full_catalog_size=10,
        scored=False,
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
        coverage="Applicability overlay (not scored): risks evidenced by observed agentic findings",
        full_catalog_size=10,
        scored=False,
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
        coverage=(
            "Applicability overlay (not scored): LLM/AI techniques — prompt injection, jailbreak, "
            "supply-chain, exfiltration, agent tool abuse — that the observed findings make applicable"
        ),
        # ATLAS is the AI counterpart of ATT&CK: an adversary TECHNIQUE matrix,
        # which is why this entry's own catalog and unit are "techniques". The
        # argument that keeps ATT&CK unscored applies verbatim — a technique is
        # APPLICABLE or not, it cannot be passed or failed. Scoring all 65 as
        # controls asserted 65 unevidenced failures and, being the single largest
        # scored framework, dominated overall_score with them.
        scored=False,
    ),
    ComplianceFrameworkMetadata(
        family="MITRE",
        framework="ATT&CK Enterprise",
        slug="attack",
        output_key="mitre_attack",
        summary_prefix="attack",
        tag_field="attack_tags",
        catalog=get_bundled_attack_techniques(),
        report_label="MITRE ATT&CK",
        bundled_unit="techniques",
        source_standard_size="~700",
        coverage=(
            "Applicability overlay (not scored): techniques MITRE's CWE → CAPEC → ATT&CK data "
            "associates with the weaknesses observed in the estate"
        ),
        # ATT&CK describes adversary behaviour, not controls an estate implements.
        # A technique is APPLICABLE or not; it cannot pass or fail, and scoring it
        # as a failing control asserted dozens of unevidenced failures per CVE.
        scored=False,
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
        # The bundled IDs are sub-requirements (6.2.4, 11.3.1, …), not the 12
        # top-level requirements. Labelling them "12 requirements" against a
        # source size of "12" read as complete PCI coverage, which it is not:
        # they touch requirements 2, 6, 8, 11 and 12 only.
        bundled_unit="sub-requirements",
        source_standard_size="12 top-level requirements",
        coverage="Requirements 2, 6, 8, 11, 12 for vulnerable-package and evidence risk",
    ),
)

# One authoritative inventory for every framework-tag field carried by both
# BlastRadius and Finding. Reconstructors and exporters must consume this
# registry instead of maintaining partial literal tuples that silently drift.
COMPLIANCE_TAG_FIELDS: tuple[str, ...] = tuple(metadata.tag_field for metadata in TAG_MAPPED_FRAMEWORKS)


def blast_radius_tag_kwargs(payload: Mapping[str, object]) -> dict[str, list[str]]:
    """Return normalized BlastRadius tag kwargs from a serialized payload."""
    normalized: dict[str, list[str]] = {}
    for field in COMPLIANCE_TAG_FIELDS:
        raw = payload.get(field)
        normalized[field] = [str(tag) for tag in raw] if isinstance(raw, (list, tuple, set)) else []
    return normalized


# Some frameworks emit their tags namespaced (``FedRAMP-SI-10``) while their
# catalog is keyed on the bare control id. Every consumer that joins a tag to a
# catalog must go through this one resolver — when only the evidence exporter
# normalized, FedRAMP evidence rows carried findings while the status summary in
# the same document reported zero evaluated controls.
_TAG_NAMESPACE_PREFIXES: tuple[str, ...] = ("FedRAMP-", "CMMC-", "NIST-", "ISO-", "SOC2-", "CIS-", "PCI-")


def control_key_for_tag(tag: str, catalog: Mapping[str, str]) -> str | None:
    """Resolve an emitted compliance tag to its catalog key, or None if unmapped."""
    value = tag.strip()
    if value in catalog:
        return value
    for prefix in _TAG_NAMESPACE_PREFIXES:
        if value.startswith(prefix) and value.removeprefix(prefix) in catalog:
            return value.removeprefix(prefix)
    return None


# Canonical hyphenated slugs (``TAG_MAPPED_FRAMEWORKS``) vs legacy ingest aliases.
FRAMEWORK_SLUG_ALIASES: dict[str, str] = {
    "mitre-attack": "attack",
    "mitre_attack": "attack",
    "pci_dss": "pci-dss",
}


def normalize_framework_slug(slug: str) -> str:
    """Normalize API/ingest framework slugs to canonical hyphenated form."""
    normalized = slug.strip().lower().replace("_", "-")
    return FRAMEWORK_SLUG_ALIASES.get(normalized, normalized)


_FRAMEWORK_IDENT_RE = re.compile(r"[^a-z0-9]+")


def _normalize_framework_ident(value: str) -> str:
    """Lowercase and strip every non-alphanumeric character.

    Collapses the small representational differences between the compliance
    UI's section id, the metadata ``slug``, its ``output_key`` and its
    ``tag_field`` so all three forms of one framework compare equal
    (``nist-csf`` == ``nist_csf`` == ``nistcsf``).
    """
    return _FRAMEWORK_IDENT_RE.sub("", value.strip().lower())


def resolve_framework_filter(value: str) -> ComplianceFrameworkMetadata | None:
    """Resolve a UI/API framework identifier to its tag-mapped metadata.

    The compliance drill-through links to ``/findings?framework=<section id>``
    where the section id is the UI slug (``nist-csf``, ``iso27001``,
    ``nist-ai-rmf`` …). Those do not always equal the metadata ``slug`` /
    ``output_key`` / ``tag_field`` (``nist-ai-rmf`` maps to slug ``nist``,
    ``iso27001`` to ``iso-27001``), so match tolerantly against all three,
    normalized. Returns ``None`` for an unrecognized identifier so the caller
    can return an honest empty result rather than raising.
    """
    key = _normalize_framework_ident(value)
    if not key:
        return None
    for meta in TAG_MAPPED_FRAMEWORKS:
        candidates = {
            _normalize_framework_ident(meta.slug),
            _normalize_framework_ident(meta.output_key),
            _normalize_framework_ident(meta.tag_field.removesuffix("_tags")),
        }
        if key in candidates:
            return meta
    return None


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


def scored_framework_slugs() -> frozenset[str]:
    """Canonical framework slugs that carry pass/warn/fail semantics."""

    return frozenset(metadata.slug for metadata in TAG_MAPPED_FRAMEWORKS if metadata.scored)


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
