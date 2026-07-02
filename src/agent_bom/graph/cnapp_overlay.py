"""Cloud-CNAPP enrichment: internet exposure, data stores, and toxic chains.

Derives network-exposure and data-at-rest structure from signals already in
the graph (CIS/IaC misconfigurations + cloud resources), without needing new
scanner inputs:

- Cloud resources flagged public/internet-reachable by a misconfiguration are
  marked ``internet_exposed`` and linked ``EXPOSED_TO`` the data stores they can
  reach.
- Data-store-like cloud resources (buckets, databases, lakes, warehouses) gain a
  ``DATA_STORE`` companion node via ``STORES`` so path-to-sensitive-data is
  traversable.
- An exposed + vulnerable resource is recorded as a toxic combination — the
  classic "internet-reachable and exploitable" chain.
"""

from __future__ import annotations

from agent_bom.graph.container import InteractionRisk, UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType, NodeStatus, RelationshipType

_OVERLAY_SOURCE = "cnapp-overlay"

# Keywords that, in a misconfiguration label/finding, indicate public exposure.
_EXPOSURE_KEYWORDS = (
    "public",
    "0.0.0.0/0",
    "::/0",
    "internet",
    "anonymous",
    "unauthenticated",
    "publicly accessible",
    "world-readable",
    "open to the world",
    "allow_all",
)

# Keywords that mark a cloud resource as a data store.
_DATA_STORE_KEYWORDS = (
    "s3",
    "bucket",
    "blob",
    "storage account",
    "rds",
    "database",
    "dynamodb",
    "cosmos",
    "datalake",
    "data lake",
    "bigquery",
    "redshift",
    "snowflake",
    "warehouse",
    "gcs",
    "cloud storage",
    "efs",
    "filestore",
)


_SENSITIVE_KEYWORDS = (
    "pii",
    "phi",
    "personal data",
    "personally identifiable",
    "gdpr",
    "hipaa",
    "pci",
    "ssn",
    "social security",
    "credit card",
    "secret",
    "credential",
    "confidential",
    "biometric",
    "protected health",
    "financial record",
    "passport",
    "bank account",
    "sensitive",
)


def _text_of(node: UnifiedNode) -> str:
    parts = [node.label]
    for key in ("description", "rule", "rule_id", "title", "resource_type", "service", "name"):
        val = node.attributes.get(key)
        if isinstance(val, str):
            parts.append(val)
    return " ".join(parts).lower()


def _sensitive_text(node: UnifiedNode) -> str:
    """Gather the text that may signal the node holds sensitive data."""
    parts = [node.label]
    desc = node.attributes.get("description")
    if isinstance(desc, str):
        parts.append(desc)
    parts.extend(str(tag) for tag in node.compliance_tags)
    flags = node.attributes.get("security_flags")
    if isinstance(flags, list):
        for flag in flags:
            if isinstance(flag, dict):
                parts.append(str(flag.get("type", "")))
                parts.append(str(flag.get("description", "")))
            else:
                parts.append(str(flag))
    for key in ("task_categories", "features", "data_classification"):
        val = node.attributes.get(key)
        if isinstance(val, list):
            parts.extend(str(item) for item in val)
        elif isinstance(val, str):
            parts.append(val)
    # Cloud resources carry data classification natively, but each provider uses
    # a different carrier — AWS/Azure resource ``tags`` and GCP ``labels`` (e.g.
    # ``{"classification": "pii"}``). Feed both keys and values into the one
    # shared classifier so every cloud's native sensitivity marker is honoured
    # without a per-provider code path (Snowflake carries it via sensitive_objects).
    for key in ("tags", "labels"):
        bag = node.attributes.get(key)
        if isinstance(bag, dict):
            for tag_key, tag_val in bag.items():
                parts.append(str(tag_key))
                parts.append(str(tag_val))
        elif isinstance(bag, list):
            parts.extend(str(item) for item in bag)
    classification = node.attributes.get("content_classification")
    if isinstance(classification, dict):
        for key in (
            "schema_version",
            "status",
            "data_sensitivity",
            "sensitivity_score",
            "total_findings",
            "objects_sampled",
        ):
            val = classification.get(key)
            if isinstance(val, str | int | float):
                parts.append(str(val))
        for key in ("findings_by_type", "classification_counts"):
            counts = classification.get(key)
            if isinstance(counts, dict):
                for finding_type, count in counts.items():
                    finding_text = str(finding_type)
                    parts.append(finding_text)
                    parts.append(finding_text.replace("_", " "))
                    parts.append(str(count))
        frameworks = classification.get("data_regulatory_frameworks")
        if isinstance(frameworks, list):
            parts.extend(str(item) for item in frameworks)
        top_findings = classification.get("top_findings")
        if isinstance(top_findings, list):
            for finding in top_findings:
                if not isinstance(finding, dict):
                    continue
                pii_type = str(finding.get("pii_type", ""))
                parts.append(pii_type)
                parts.append(pii_type.replace("_", " "))
                parts.append(str(finding.get("severity", "")))
    return " ".join(parts).lower()


def _matches(text: str, keywords: tuple[str, ...]) -> bool:
    return any(kw in text for kw in keywords)


def _is_sensitive(node: UnifiedNode) -> bool:
    return _matches(_sensitive_text(node), _SENSITIVE_KEYWORDS)


# Regulatory frameworks inferred from METADATA only (labels, compliance tags,
# dataset-card flags) — never from data contents. Ordered by remediation
# severity so the first match names the headline regulation at risk. The first
# three are high-sensitivity regimes that escalate an exposed store to the
# "restricted" tier.
_REGULATORY_FRAMEWORKS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("PCI-DSS", "card data", ("pci", "credit card", "cardholder", "card data", "bank account")),
    ("HIPAA", "protected health information", ("phi", "hipaa", "protected health", "health record", "medical record")),
    (
        "GDPR",
        "personal data",
        ("gdpr", "pii", "personal data", "personally identifiable", "ssn", "social security", "passport", "biometric"),
    ),
    ("SOC2", "secrets/credentials", ("secret", "credential", "confidential")),
)
_HIGH_SENSITIVITY_FRAMEWORKS = frozenset({"PCI-DSS", "HIPAA", "GDPR"})


def _classify_regulatory_frameworks(node: UnifiedNode) -> list[str]:
    """Regulatory frameworks a data node is subject to, by metadata signals.

    Returns framework codes in remediation-severity order (PCI-DSS, HIPAA,
    GDPR, SOC2); empty when only the generic ``sensitive`` keyword matched.
    """
    text = _sensitive_text(node)
    return [code for code, _label, kws in _REGULATORY_FRAMEWORKS if _matches(text, kws)]


def _framework_label(code: str) -> str:
    for c, label, _kws in _REGULATORY_FRAMEWORKS:
        if c == code:
            return f"{c} {label}"
    return code


def _content_classification_evidence(node: UnifiedNode) -> dict[str, object]:
    """Stable, redacted DSPM sampling evidence copied onto DATA_STORE nodes."""
    classification = node.attributes.get("content_classification")
    if not isinstance(classification, dict):
        return {}
    evidence: dict[str, object] = {"data_classification_source": "content_sampling"}
    for source_key, target_key in (
        ("schema_version", "content_classification_schema"),
        ("status", "content_classification_status"),
        ("sensitivity_score", "content_sensitivity_score"),
        ("data_sensitivity", "content_data_sensitivity"),
        ("total_findings", "content_classification_findings"),
        ("objects_sampled", "content_objects_sampled"),
        ("rows_sampled", "content_rows_sampled"),
        ("columns_sampled", "content_columns_sampled"),
        ("tables_sampled", "content_tables_sampled"),
        ("warnings", "content_classification_warnings"),
        ("redaction", "content_classification_redaction"),
    ):
        value = classification.get(source_key)
        if value not in (None, "", [], {}):
            evidence[target_key] = value
    for source_key in ("findings_by_type", "classification_counts"):
        counts = classification.get(source_key)
        if isinstance(counts, dict) and counts:
            evidence["content_classification_counts"] = dict(counts)
            break
    return evidence


def apply_cnapp_overlay(graph: UnifiedGraph) -> dict[str, int]:
    """Enrich ``graph`` with exposure + data-store structure in place.

    Returns counts of exposed nodes, data stores, and toxic combinations added.
    Never raises into the builder.
    """
    nodes = list(graph.nodes.values())
    cloud_resources = [n for n in nodes if n.entity_type in (EntityType.CLOUD_RESOURCE, EntityType.RESOURCE, EntityType.SERVER)]
    misconfigs = [n for n in nodes if n.entity_type == EntityType.MISCONFIGURATION]

    # Resource id → set of vulnerability node ids affecting it (via VULNERABLE_TO).
    vulnerable_resources: set[str] = set()
    for edge in graph.edges:
        if edge.relationship == RelationshipType.VULNERABLE_TO:
            vulnerable_resources.add(edge.source)

    # Resources fronted by a WAF / API gateway (a PROTECTS edge). A protected
    # resource's internet exposure is mitigated — its exposure verdict is
    # downgraded below an unprotected peer's so the graph does not score a
    # WAF-fronted asset identically to a bare one.
    protected_ids: set[str] = set()
    for edge in graph.edges:
        if edge.relationship == RelationshipType.PROTECTS:
            protected_ids.add(edge.target)

    # Map a misconfiguration to the resources it AFFECTS so exposure can attach
    # to the real asset rather than the finding node.
    affected_by_misconfig: dict[str, list[str]] = {}
    for edge in graph.edges:
        if edge.relationship == RelationshipType.AFFECTS:
            affected_by_misconfig.setdefault(edge.source, []).append(edge.target)

    exposed_ids: set[str] = set()
    for mc in misconfigs:
        # Prefer structured network_exposure (open ports/CIDR to the internet,
        # emitted by the cloud scanner) over keyword-matching the evidence text.
        structured = [e for e in (mc.attributes.get("network_exposure") or []) if isinstance(e, dict) and e.get("scope") == "internet"]
        if not structured and not _matches(_text_of(mc), _EXPOSURE_KEYWORDS):
            continue
        ports = [{"from_port": e.get("from_port"), "to_port": e.get("to_port"), "protocol": e.get("protocol", "tcp")} for e in structured]
        for target_id in affected_by_misconfig.get(mc.id, []):
            node = graph.nodes.get(target_id)
            if node is not None:
                node.attributes["internet_exposed"] = True
                exposed_ids.add(target_id)
                if ports:
                    node.attributes.setdefault("exposed_ports", []).extend(ports)
    # Also mark cloud resources whose own attributes/label signal public exposure.
    for node in cloud_resources:
        if node.attributes.get("internet_exposed") or _matches(_text_of(node), _EXPOSURE_KEYWORDS):
            node.attributes["internet_exposed"] = True
            exposed_ids.add(node.id)

    # Record exposure mitigation on every protected + exposed resource so its
    # verdict differs from an unprotected peer, whether or not it is vulnerable.
    mitigated = 0
    for resource_id in exposed_ids & protected_ids:
        node = graph.nodes.get(resource_id)
        if node is None:
            continue
        node.attributes["exposure_mitigated"] = True
        node.attributes["protected_by_waf"] = True
        mitigated += 1

    # Classify data stores and attach a DATA_STORE companion node.
    data_stores_added = 0
    data_store_for_resource: dict[str, str] = {}
    for node in cloud_resources:
        if node.entity_type == EntityType.SERVER:
            continue
        if not _matches(_text_of(node), _DATA_STORE_KEYWORDS):
            continue
        ds_id = f"data_store:{node.id}"
        data_store_for_resource[node.id] = ds_id
        if ds_id not in graph.nodes:
            graph.add_node(
                UnifiedNode(
                    id=ds_id,
                    entity_type=EntityType.DATA_STORE,
                    label=f"data: {node.label}",
                    severity="info",
                    data_sources=[_OVERLAY_SOURCE],
                    attributes={"backed_by": node.id, "internet_exposed": bool(node.attributes.get("internet_exposed"))},
                )
            )
            data_stores_added += 1
        graph.nodes[ds_id].attributes.update(_content_classification_evidence(node))
        graph.add_edge(
            UnifiedEdge(
                source=node.id,
                target=ds_id,
                relationship=RelationshipType.STORES,
                provenance={"source": _OVERLAY_SOURCE},
            )
        )

    # EXPOSED_TO: an internet-exposed resource reaches the data stores it backs.
    for resource_id in exposed_ids:
        exposed_ds = data_store_for_resource.get(resource_id)
        if exposed_ds:
            graph.add_edge(
                UnifiedEdge(
                    source=resource_id,
                    target=exposed_ds,
                    relationship=RelationshipType.EXPOSED_TO,
                    weight=6.0,
                    provenance={"source": _OVERLAY_SOURCE},
                    evidence={"reason": "internet_exposed_data_store"},
                )
            )

    # Toxic combinations: internet-exposed AND vulnerable. A WAF/API-gateway in
    # front of the resource mitigates the exposure, so the verdict is downgraded
    # (lower risk, distinct pattern) instead of the full toxic escalation.
    toxic = 0
    toxic_mitigated = 0
    for resource_id in sorted(exposed_ids & vulnerable_resources):
        node = graph.nodes.get(resource_id)
        if node is None:
            continue
        if resource_id in protected_ids:
            node.attributes["toxic_exposed_vulnerable_mitigated"] = True
            if node.risk_score < 6.5:
                node.risk_score = 6.5
            graph.interaction_risks.append(
                InteractionRisk(
                    pattern="internet_exposed_vulnerable_mitigated",
                    agents=[node.label],
                    risk_score=6.5,
                    description=(
                        f"{node.label} carries a known vulnerability and is internet-exposed but fronted by a WAF/API gateway "
                        "(exposure mitigated)."
                    ),
                    owasp_agentic_tag=None,
                )
            )
            toxic_mitigated += 1
            continue
        node.attributes["toxic_exposed_vulnerable"] = True
        if node.risk_score < 9.0:
            node.risk_score = 9.0
        node.status = NodeStatus.VULNERABLE
        graph.interaction_risks.append(
            InteractionRisk(
                pattern="internet_exposed_vulnerable",
                agents=[node.label],
                risk_score=9.5,
                description=f"{node.label} is internet-exposed and carries a known vulnerability (toxic combination).",
                owasp_agentic_tag=None,
            )
        )
        toxic += 1

    # ── Data sensitivity (PII/PHI/secrets) on datasets and data stores ──
    sensitive_ids: set[str] = set()
    for node in graph.nodes.values():
        if node.entity_type not in (EntityType.DATASET, EntityType.DATA_STORE):
            continue
        backing = graph.nodes.get(node.attributes.get("backed_by", "")) if node.entity_type == EntityType.DATA_STORE else None
        if _is_sensitive(node) or (backing is not None and _is_sensitive(backing)):
            node.attributes["data_sensitivity"] = "sensitive"
            # Which regulatory regimes govern this store (PCI/HIPAA/GDPR/SOC2),
            # merged from the store and the resource it backs — metadata only.
            frameworks = _classify_regulatory_frameworks(node)
            if backing is not None:
                for code in _classify_regulatory_frameworks(backing):
                    if code not in frameworks:
                        frameworks.append(code)
            if frameworks:
                node.attributes["data_regulatory_frameworks"] = frameworks
            sensitive_ids.add(node.id)

    # Who/what can reach sensitive data stores. This is intentionally derived
    # from existing permission/runtime edges so DSPM risk follows the same graph
    # evidence as the rest of ContextGraph.
    access_relationships = {
        RelationshipType.CAN_ACCESS,
        RelationshipType.HAS_PERMISSION,
        RelationshipType.ACCESSED,
        RelationshipType.STORES,
        RelationshipType.EXPOSED_TO,
    }
    sensitive_access_paths = 0
    for node_id in sorted(sensitive_ids):
        node = graph.nodes.get(node_id)
        if node is None:
            continue
        subjects: list[dict[str, str]] = []
        seen_subjects: set[str] = set()
        for edge in graph.edges:
            if edge.target != node_id or edge.relationship not in access_relationships:
                continue
            if edge.source == node.attributes.get("backed_by"):
                continue
            source = graph.nodes.get(edge.source)
            if source is None or source.id in seen_subjects:
                continue
            seen_subjects.add(source.id)
            subjects.append(
                {
                    "id": source.id,
                    "label": source.label,
                    "entity_type": source.entity_type.value,
                    "relationship": edge.relationship.value,
                }
            )
        if not subjects:
            continue
        sensitive_access_paths += len(subjects)
        node.attributes["sensitive_data_access_subjects"] = subjects[:25]
        node.attributes["sensitive_data_access_count"] = len(subjects)
        if node.risk_score < 7.0:
            node.risk_score = 7.0
        graph.interaction_risks.append(
            InteractionRisk(
                pattern="sensitive_data_reachable",
                agents=[node.label],
                risk_score=7.0,
                description=f"{node.label} holds sensitive data and is reachable by {len(subjects)} identity/tool path(s).",
                owasp_agentic_tag=None,
            )
        )

    # Toxic: sensitive data that is internet-exposed.
    exposed_sensitive = 0
    for node_id in sorted(sensitive_ids):
        node = graph.nodes.get(node_id)
        if node is None or not node.attributes.get("internet_exposed"):
            continue
        node.attributes["toxic_exposed_sensitive"] = True
        if node.risk_score < 9.5:
            node.risk_score = 9.5
        node.severity = "high"
        node.status = NodeStatus.VULNERABLE
        # Exposed + governed by a high-sensitivity regime → "restricted"; an
        # exposed store with only generic sensitivity → "confidential".
        frameworks = node.attributes.get("data_regulatory_frameworks") or []
        node.attributes["data_classification_tier"] = (
            "restricted" if any(f in _HIGH_SENSITIVITY_FRAMEWORKS for f in frameworks) else "confidential"
        )
        regulation = f" ({_framework_label(frameworks[0])})" if frameworks else ""
        graph.interaction_risks.append(
            InteractionRisk(
                pattern="internet_exposed_sensitive_data",
                agents=[node.label],
                risk_score=9.7,
                description=f"{node.label} holds sensitive data{regulation} and is internet-exposed (path to sensitive data).",
                owasp_agentic_tag=None,
            )
        )
        exposed_sensitive += 1

    return {
        "exposed_nodes": len(exposed_ids),
        "data_stores_added": data_stores_added,
        "toxic_combinations": toxic,
        "toxic_combinations_mitigated": toxic_mitigated,
        "exposure_mitigated_nodes": mitigated,
        "sensitive_data_nodes": len(sensitive_ids),
        "sensitive_data_access_paths": sensitive_access_paths,
        "exposed_sensitive_data": exposed_sensitive,
    }
