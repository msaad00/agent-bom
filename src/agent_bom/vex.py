"""VEX (Vulnerability Exploitability eXchange) support.

Provides VEX document generation, ingestion, and application to scan results.
Supports OpenVEX JSON format (https://openvex.dev/).
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport


class VexStatus(str, Enum):
    """VEX vulnerability status."""

    AFFECTED = "affected"
    NOT_AFFECTED = "not_affected"
    FIXED = "fixed"
    UNDER_INVESTIGATION = "under_investigation"


class VexJustification(str, Enum):
    """Justification for NOT_AFFECTED status (required by OpenVEX spec)."""

    COMPONENT_NOT_PRESENT = "component_not_present"
    VULNERABLE_CODE_NOT_PRESENT = "vulnerable_code_not_present"
    VULNERABLE_CODE_NOT_IN_EXECUTE_PATH = "vulnerable_code_not_in_execute_path"
    VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY = "vulnerable_code_cannot_be_controlled_by_adversary"
    INLINE_MITIGATIONS_ALREADY_EXIST = "inline_mitigations_already_exist"


@dataclass
class VexStatement:
    """A single VEX statement about a vulnerability's exploitability."""

    vulnerability_id: str  # CVE-YYYY-NNNNN or GHSA-xxxx
    status: VexStatus
    justification: VexJustification | None = None  # Required when NOT_AFFECTED
    impact_statement: str | None = None
    action_statement: str | None = None  # Recommended when AFFECTED
    products: list[str] = field(default_factory=list)  # Package PURLs
    timestamp: str = ""  # ISO 8601
    author: str = "agent-bom"

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


@dataclass
class VexDocument:
    """A VEX document containing statements about vulnerability exploitability."""

    statements: list[VexStatement] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if not self.metadata:
            self.metadata = {
                "id": f"urn:uuid:{uuid.uuid4()}",
                "author": "agent-bom",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": 1,
            }


# ---------------------------------------------------------------------------
# Load VEX documents
# ---------------------------------------------------------------------------


def load_vex(path: str) -> VexDocument:
    """Load a VEX document from a JSON file.

    Supports OpenVEX format:
    {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "statements": [{"vulnerability": {"name": "CVE-..."}, "status": "..."}]
    }

    Also supports simplified format:
    {
      "statements": [{"vulnerability_id": "CVE-...", "status": "..."}]
    }
    """
    with open(path) as f:
        data = json.load(f)

    statements = []
    for stmt_data in data.get("statements", []):
        # OpenVEX format
        if "vulnerability" in stmt_data and isinstance(stmt_data["vulnerability"], dict):
            vuln_id = stmt_data["vulnerability"].get("name", stmt_data["vulnerability"].get("id", ""))
        else:
            vuln_id = stmt_data.get("vulnerability_id", stmt_data.get("vulnerability", ""))

        status_str = stmt_data.get("status", "under_investigation")
        try:
            status = VexStatus(status_str)
        except ValueError:
            status = VexStatus.UNDER_INVESTIGATION

        justification = None
        just_str = stmt_data.get("justification")
        if just_str:
            try:
                justification = VexJustification(just_str)
            except ValueError:
                logger.warning("Unknown VEX justification value: %s", just_str)

        products = stmt_data.get("products", [])
        if isinstance(products, list) and products and isinstance(products[0], dict):
            products = [p.get("@id", p.get("purl", "")) for p in products]

        statements.append(
            VexStatement(
                vulnerability_id=vuln_id or "",
                status=status,
                justification=justification,
                impact_statement=stmt_data.get("impact_statement"),
                action_statement=stmt_data.get("action_statement"),
                products=products,
                timestamp=stmt_data.get("timestamp", ""),
                author=stmt_data.get("author", data.get("author", "unknown")),
            )
        )

    metadata = {
        "id": data.get("@id", data.get("id", f"urn:uuid:{uuid.uuid4()}")),
        "author": data.get("author", "unknown"),
        "timestamp": data.get("timestamp", ""),
        "version": data.get("version", 1),
    }

    return VexDocument(statements=statements, metadata=metadata)


# ---------------------------------------------------------------------------
# Generate VEX from scan results
# ---------------------------------------------------------------------------


def generate_vex(report: "AIBOMReport", auto_triage: bool = False) -> VexDocument:
    """Generate a VEX document from scan results.

    If auto_triage is True:
    - KEV vulns → AFFECTED with action_statement
    - Transitive-only deps → UNDER_INVESTIGATION
    - Everything else → UNDER_INVESTIGATION
    """
    statements = []
    seen_vulns: set[str] = set()

    for br in report.blast_radii:
        vuln = br.vulnerability
        if vuln.id in seen_vulns:
            continue
        seen_vulns.add(vuln.id)

        # Collect affected PURLs
        products = []
        if br.package:
            products.append(br.package.purl or f"pkg:{br.package.ecosystem}/{br.package.name}@{br.package.version}")

        # CWE-aware triage: use impact category and reachability
        impact_cat = getattr(br, "impact_category", "code-execution")
        reachability = br.reachability
        attack_summary = getattr(br, "attack_vector_summary", None)

        impact_parts = [f"Severity: {vuln.severity.value}"]
        if vuln.cvss_score:
            impact_parts.append(f"CVSS: {vuln.cvss_score}")
        impact_parts.append(f"Impact: {impact_cat}")
        impact_parts.append(f"Reachability: {reachability}")
        if attack_summary:
            impact_parts.append(attack_summary)
        impact_text = ". ".join(impact_parts)

        if auto_triage and vuln.is_kev:
            statements.append(
                VexStatement(
                    vulnerability_id=vuln.id,
                    status=VexStatus.AFFECTED,
                    action_statement=f"CISA KEV: exploit known in the wild. Patch to {vuln.fixed_version or 'latest'}.",
                    impact_statement=impact_text,
                    products=products,
                )
            )
        elif auto_triage and impact_cat in ("availability", "client-side") and reachability == "unlikely":
            # DoS/XSS in transitive dep with no credential exposure → not affected
            statements.append(
                VexStatement(
                    vulnerability_id=vuln.id,
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    impact_statement=impact_text,
                    products=products,
                )
            )
        else:
            statements.append(
                VexStatement(
                    vulnerability_id=vuln.id,
                    status=VexStatus.UNDER_INVESTIGATION,
                    impact_statement=impact_text,
                    products=products,
                )
            )

    return VexDocument(statements=statements)


# ---------------------------------------------------------------------------
# Apply VEX to scan results
# ---------------------------------------------------------------------------


_VEX_SUPPRESSED_STATUSES = frozenset({VexStatus.NOT_AFFECTED.value, VexStatus.FIXED.value})


def is_vex_suppressed(vuln) -> bool:
    """Return True if a vulnerability is suppressed by VEX (not_affected or fixed)."""
    return vuln.vex_status in _VEX_SUPPRESSED_STATUSES


def apply_vex(report: "AIBOMReport", vex: VexDocument) -> int:
    """Apply VEX statements to a report's vulnerabilities.

    Sets vex_status and vex_justification on matching Vulnerability objects.
    Vulnerabilities with status ``not_affected`` or ``fixed`` are considered
    suppressed — they remain in the data model for audit but are excluded
    from counts, exit codes, and severity-gate logic via :func:`is_vex_suppressed`.
    Returns count of vulnerabilities updated.
    """
    # Build lookup: vuln_id → statement
    vex_map: dict[str, VexStatement] = {}
    for stmt in vex.statements:
        vex_map[stmt.vulnerability_id] = stmt

    count = 0
    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                for vuln in pkg.vulnerabilities:
                    matched_stmt: VexStatement | None = vex_map.get(vuln.id)
                    if not matched_stmt:
                        # Check aliases
                        for alias in vuln.aliases or []:
                            matched_stmt = vex_map.get(alias)
                            if matched_stmt:
                                break
                    if matched_stmt:
                        vuln.vex_status = matched_stmt.status.value
                        vuln.vex_justification = matched_stmt.justification.value if matched_stmt.justification else None
                        count += 1

    return count


# ---------------------------------------------------------------------------
# Export VEX documents
# ---------------------------------------------------------------------------


def export_openvex(doc: VexDocument) -> dict:
    """Serialize to OpenVEX JSON format (https://openvex.dev/ns/v0.2.0)."""
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": doc.metadata.get("id", f"urn:uuid:{uuid.uuid4()}"),
        "author": doc.metadata.get("author", "agent-bom"),
        "timestamp": doc.metadata.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "version": doc.metadata.get("version", 1),
        "statements": [
            {
                "vulnerability": {"name": stmt.vulnerability_id},
                "status": stmt.status.value,
                **({"justification": stmt.justification.value} if stmt.justification else {}),
                **({"impact_statement": stmt.impact_statement} if stmt.impact_statement else {}),
                **({"action_statement": stmt.action_statement} if stmt.action_statement else {}),
                "products": [{"@id": p} for p in stmt.products] if stmt.products else [],
                "timestamp": stmt.timestamp,
            }
            for stmt in doc.statements
        ],
    }


def to_serializable(doc: VexDocument) -> dict:
    """Convert VEX document to a simplified JSON-serializable dict."""
    return {
        "metadata": doc.metadata,
        "statements": [
            {
                "vulnerability_id": stmt.vulnerability_id,
                "status": stmt.status.value,
                "justification": stmt.justification.value if stmt.justification else None,
                "impact_statement": stmt.impact_statement,
                "action_statement": stmt.action_statement,
                "products": stmt.products,
                "timestamp": stmt.timestamp,
                "author": stmt.author,
            }
            for stmt in doc.statements
        ],
        "stats": {
            "total_statements": len(doc.statements),
            "affected": sum(1 for s in doc.statements if s.status == VexStatus.AFFECTED),
            "not_affected": sum(1 for s in doc.statements if s.status == VexStatus.NOT_AFFECTED),
            "fixed": sum(1 for s in doc.statements if s.status == VexStatus.FIXED),
            "under_investigation": sum(1 for s in doc.statements if s.status == VexStatus.UNDER_INVESTIGATION),
        },
    }
