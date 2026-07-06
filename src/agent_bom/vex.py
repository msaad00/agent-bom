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

_CDX_STATE_TO_VEX: dict[str, VexStatus] = {
    "not_affected": VexStatus.NOT_AFFECTED,
    "exploitable": VexStatus.AFFECTED,
    "resolved": VexStatus.FIXED,
    "resolved_with_pedigree": VexStatus.FIXED,
    "in_triage": VexStatus.UNDER_INVESTIGATION,
    "false_positive": VexStatus.NOT_AFFECTED,
}

_CDX_JUSTIFICATION_TO_VEX: dict[str, VexJustification] = {
    "code_not_present": VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    "code_not_reachable": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "requires_configuration": VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
    "requires_dependency": VexJustification.COMPONENT_NOT_PRESENT,
    "requires_environment": VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY,
    "protected_by_compiler": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "protected_at_runtime": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "protected_at_perimeter": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
    "protected_by_mitigating_control": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
}

_CSAF_STATUS_TO_VEX: dict[str, VexStatus] = {
    "fixed": VexStatus.FIXED,
    "known_not_affected": VexStatus.NOT_AFFECTED,
    "known_affected": VexStatus.AFFECTED,
    "under_investigation": VexStatus.UNDER_INVESTIGATION,
    "first_fixed": VexStatus.FIXED,
}

_CSAF_FLAG_TO_VEX: dict[str, VexJustification] = {
    "component_not_present": VexJustification.COMPONENT_NOT_PRESENT,
    "vulnerable_code_not_present": VexJustification.VULNERABLE_CODE_NOT_PRESENT,
    "vulnerable_code_not_in_execute_path": VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
    "vulnerable_code_cannot_be_controlled_by_adversary": (
        VexJustification.VULNERABLE_CODE_CANNOT_BE_CONTROLLED_BY_ADVERSARY
    ),
    "inline_mitigations_already_exist": VexJustification.INLINE_MITIGATIONS_ALREADY_EXIST,
}


def _detect_vex_format(data: dict) -> str:
    vulnerabilities = data.get("vulnerabilities")
    if data.get("bomFormat") == "CycloneDX" and isinstance(vulnerabilities, list):
        if any(isinstance(entry, dict) and entry.get("analysis") for entry in vulnerabilities):
            return "cyclonedx"
    document = data.get("document")
    if isinstance(document, dict):
        if document.get("category") == "csaf_vex":
            return "csaf"
        if document.get("csaf_version") and vulnerabilities:
            return "csaf"
    if isinstance(vulnerabilities, list) and vulnerabilities:
        first = vulnerabilities[0]
        if isinstance(first, dict) and "product_status" in first:
            return "csaf"
    if data.get("@context", "").startswith("https://openvex.dev/") or "statements" in data:
        return "openvex"
    return "openvex"


def _extract_cdx_product_ref(ref: str) -> str:
    if not ref:
        return ""
    if "#" in ref:
        return ref.rsplit("#", 1)[-1]
    return ref


def _parse_cyclonedx_vex(data: dict) -> VexDocument:
    statements: list[VexStatement] = []
    for entry in data.get("vulnerabilities", []):
        if not isinstance(entry, dict):
            continue
        vuln_id = entry.get("id") or entry.get("bom-ref") or ""
        analysis = entry.get("analysis") or {}
        if not isinstance(analysis, dict):
            continue
        state_raw = str(analysis.get("state") or "under_investigation").lower()
        try:
            status = _CDX_STATE_TO_VEX.get(state_raw, VexStatus.UNDER_INVESTIGATION)
        except ValueError:
            status = VexStatus.UNDER_INVESTIGATION

        justification = None
        just_raw = analysis.get("justification")
        if just_raw:
            justification = _CDX_JUSTIFICATION_TO_VEX.get(str(just_raw).lower())
            if justification is None:
                logger.warning("Unknown CycloneDX VEX justification value: %s", just_raw)

        products = [
            _extract_cdx_product_ref(aff.get("ref", ""))
            for aff in entry.get("affects", [])
            if isinstance(aff, dict) and aff.get("ref")
        ]
        detail = analysis.get("detail")
        response = analysis.get("response")
        action_statement = None
        if isinstance(response, list) and response:
            action_statement = ", ".join(str(item) for item in response)
        timestamp = ""
        for key in ("lastUpdated", "firstIssued"):
            if analysis.get(key):
                timestamp = str(analysis[key])
                break

        author = "unknown"
        metadata = data.get("metadata")
        if isinstance(metadata, dict):
            authors = metadata.get("authors")
            if isinstance(authors, list) and authors and isinstance(authors[0], dict):
                author = authors[0].get("name", author)
            supplier = metadata.get("supplier")
            if isinstance(supplier, dict) and supplier.get("name"):
                author = supplier["name"]

        statements.append(
            VexStatement(
                vulnerability_id=vuln_id,
                status=status,
                justification=justification,
                impact_statement=detail,
                action_statement=action_statement,
                products=products,
                timestamp=timestamp,
                author=author,
            )
        )

    metadata = {
        "id": data.get("serialNumber", data.get("@id", f"urn:uuid:{uuid.uuid4()}")),
        "author": statements[0].author if statements else "unknown",
        "timestamp": data.get("metadata", {}).get("timestamp", ""),
        "version": data.get("version", 1),
        "format": "cyclonedx",
    }
    return VexDocument(statements=statements, metadata=metadata)


def _csaf_vuln_id(entry: dict) -> str:
    for key in ("cve", "ids"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
        if isinstance(value, list) and value:
            first = value[0]
            if isinstance(first, dict):
                return str(first.get("text") or first.get("id") or "")
            return str(first)
    return ""


def _csaf_impact_statement(entry: dict, product_ids: list[str]) -> str | None:
    for threat in entry.get("threats", []) or []:
        if not isinstance(threat, dict):
            continue
        if threat.get("category") == "impact" and threat.get("details"):
            threat_products = threat.get("product_ids") or []
            if not threat_products or any(pid in threat_products for pid in product_ids):
                return str(threat["details"])
    for note in entry.get("notes", []) or []:
        if isinstance(note, dict) and note.get("text"):
            return str(note["text"])
    return None


def _csaf_action_statement(entry: dict, product_ids: list[str]) -> str | None:
    for remediation in entry.get("remediations", []) or []:
        if not isinstance(remediation, dict):
            continue
        remediation_products = remediation.get("product_ids") or []
        if remediation_products and not any(pid in remediation_products for pid in product_ids):
            continue
        for key in ("details", "description"):
            if remediation.get(key):
                return str(remediation[key])
    return None


def _csaf_justification(entry: dict, product_ids: list[str]) -> VexJustification | None:
    for flag in entry.get("flags", []) or []:
        if not isinstance(flag, dict):
            continue
        flag_products = flag.get("product_ids") or []
        if flag_products and not any(pid in flag_products for pid in product_ids):
            continue
        label = str(flag.get("label") or "").lower()
        mapped = _CSAF_FLAG_TO_VEX.get(label)
        if mapped:
            return mapped
    return None


def _parse_csaf_vex(data: dict) -> VexDocument:
    statements: list[VexStatement] = []
    document = data.get("document", {})
    author = "unknown"
    publisher = document.get("publisher")
    if isinstance(publisher, dict):
        author = publisher.get("name", author)
    tracking = document.get("tracking", {})
    doc_id = tracking.get("id", f"urn:uuid:{uuid.uuid4()}")
    timestamp = tracking.get("current_release_date", tracking.get("initial_release_date", ""))

    for entry in data.get("vulnerabilities", []):
        if not isinstance(entry, dict):
            continue
        vuln_id = _csaf_vuln_id(entry)
        if not vuln_id:
            continue
        product_status = entry.get("product_status") or {}
        if not isinstance(product_status, dict):
            continue
        for status_key, product_ids in product_status.items():
            if not isinstance(product_ids, list) or not product_ids:
                continue
            status = _CSAF_STATUS_TO_VEX.get(str(status_key).lower())
            if status is None:
                logger.warning("Unknown CSAF product_status key: %s", status_key)
                continue
            justification = _csaf_justification(entry, product_ids)
            if status == VexStatus.NOT_AFFECTED and justification is None:
                justification = VexJustification.VULNERABLE_CODE_NOT_PRESENT
            statements.append(
                VexStatement(
                    vulnerability_id=vuln_id,
                    status=status,
                    justification=justification,
                    impact_statement=_csaf_impact_statement(entry, product_ids),
                    action_statement=_csaf_action_statement(entry, product_ids),
                    products=[str(pid) for pid in product_ids],
                    timestamp=timestamp,
                    author=author,
                )
            )

    metadata = {
        "id": doc_id,
        "author": author,
        "timestamp": timestamp,
        "version": tracking.get("version", 1),
        "format": "csaf",
    }
    return VexDocument(statements=statements, metadata=metadata)


def _parse_openvex(data: dict) -> VexDocument:
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
        except ValueError as exc:
            raise ValueError(f"Unknown VEX status {status_str!r}") from exc

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


def load_vex(path: str) -> VexDocument:
    """Load a VEX document from a JSON file.

    Supports OpenVEX, CycloneDX 1.5+ VEX BOMs, and CSAF 2.0 VEX advisories.
    """
    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as exc:
        raise ValueError(f"VEX JSON error in {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"VEX document in {path} must be a JSON object")

    fmt = _detect_vex_format(data)
    if fmt == "cyclonedx":
        return _parse_cyclonedx_vex(data)
    if fmt == "csaf":
        return _parse_csaf_vex(data)
    return _parse_openvex(data)


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
        if getattr(br, "symbol_reachability", None):
            impact_parts.append(f"Symbol reach: {br.symbol_reachability}")
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
        elif auto_triage and getattr(br, "symbol_reachability", None) == "unreachable":
            statements.append(
                VexStatement(
                    vulnerability_id=vuln.id,
                    status=VexStatus.NOT_AFFECTED,
                    justification=VexJustification.VULNERABLE_CODE_NOT_IN_EXECUTE_PATH,
                    action_statement=("AST symbol-reach: vulnerable package not reached from any MCP tool entrypoint."),
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
    return str(getattr(vuln, "vex_status", "") or "").lower() in _VEX_SUPPRESSED_STATUSES


def active_blast_radii(blast_radii):
    """Return blast-radius findings that are still active after VEX suppression."""

    return [br for br in blast_radii if not is_vex_suppressed(br.vulnerability)]


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

    def _match_statement(vuln) -> VexStatement | None:
        matched = vex_map.get(vuln.id)
        if matched:
            return matched
        for alias in vuln.aliases or []:
            matched = vex_map.get(alias)
            if matched:
                return matched
        return None

    def _apply_statement(vuln, stmt: VexStatement) -> None:
        vuln.vex_status = stmt.status.value
        vuln.vex_justification = stmt.justification.value if stmt.justification else None

    count = 0
    for agent in report.agents:
        for server in agent.mcp_servers:
            for pkg in server.packages:
                for vuln in pkg.vulnerabilities:
                    matched_stmt = _match_statement(vuln)
                    if matched_stmt:
                        _apply_statement(vuln, matched_stmt)
                        count += 1

    for br in report.blast_radii:
        matched_stmt = _match_statement(br.vulnerability)
        if matched_stmt:
            _apply_statement(br.vulnerability, matched_stmt)
        if is_vex_suppressed(br.vulnerability):
            br.risk_score = 0.0
            br.transitive_risk_score = 0.0

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
