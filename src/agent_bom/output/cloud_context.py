"""Carry recorded cloud inventory in standard BOM extension slots.

This is a namespaced evidence snapshot, not native software components or an
assertion of cloud coverage. Preserve provider shapes and scope instead of
guessing relationships or merging equal display names across accounts.
"""

from __future__ import annotations

import json
from typing import Any, Literal

from agent_bom.models import AIBOMReport
from agent_bom.security import sanitize_sensitive_payload

CLOUD_INVENTORY_PROPERTY = "agent-bom:cloud-inventory:v1"


def attach_cloud_context(document: dict[str, Any], report: AIBOMReport, fmt: Literal["cyclonedx", "spdx", "spdx2"]) -> dict[str, Any]:
    """Append separately sanitized evidence to an already sanitized document.

    Sanitize structured fields before JSON encoding so key-sensitive redaction
    applies and generic text sanitizers cannot corrupt the embedded JSON. The
    same string/depth limits as scan JSON apply. An absent inventory is omitted;
    explicitly empty, denied and partial payloads remain distinguishable.
    """
    if report.cloud_inventory_data is None:
        return document
    inventory = sanitize_sensitive_payload(report.cloud_inventory_data)
    evidence = {
        "schema_version": 1,
        "source": "cloud_inventory",
        "coverage": "not_assessed",
        "redaction": {"policy": "central-sanitizer", "max_string_length": 1000, "max_depth": 24},
        "inventory": inventory,
    }
    if fmt == "cyclonedx":
        document["metadata"]["properties"].append({"name": CLOUD_INVENTORY_PROPERTY, "value": json.dumps(evidence, sort_keys=True)})
        return document
    # Escape markup delimiters as JSON unicode escapes: the same annotation
    # can then travel through SPDX tag-value's <text> wrapper without injection.
    statement = json.dumps({CLOUD_INVENTORY_PROPERTY: evidence}, sort_keys=True).replace("<", "\\u003c").replace(">", "\\u003e")
    if fmt == "spdx":
        root = next(node for node in document["@graph"] if node.get("type") == "SpdxDocument")
        document["@graph"].append(
            {
                "type": "Annotation",
                "spdxId": root["spdxId"] + "/cloud-inventory",
                "creationInfo": root["creationInfo"],
                "annotationType": "other",
                "subject": root["spdxId"],
                "contentType": "application/json",
                "statement": statement,
            }
        )
    else:
        document.setdefault("annotations", []).append(
            {
                "annotationType": "OTHER",
                "annotator": "Tool: agent-bom",
                "annotationDate": document["creationInfo"]["created"],
                "comment": statement,
            }
        )
    return document
