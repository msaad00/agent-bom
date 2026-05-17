"""SARIF output for skills and instruction-file findings."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.security import sanitize_sensitive_payload

_LEVEL_BY_SEVERITY = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}
_SECURITY_SEVERITY = {
    "critical": "9.0",
    "high": "7.0",
    "medium": "4.0",
    "low": "1.0",
    "info": "0.0",
}


def skills_report_to_sarif(report: Any) -> dict[str, Any]:
    """Convert a SkillsScanReport-like object to SARIF 2.1.0."""
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rules: set[str] = set()
    report_dict = report.to_dict() if hasattr(report, "to_dict") else {}
    schema_version = report_dict.get("schema_version", "1") if isinstance(report_dict, dict) else "1"

    for file_report in getattr(report, "files", []):
        path = _relative_path(str(getattr(file_report, "path", "unknown")))
        trust = _trust_properties(file_report)
        audit = getattr(file_report, "audit", None)
        for finding in getattr(audit, "findings", []):
            category = str(getattr(finding, "category", "skill_finding") or "skill_finding")
            severity = str(getattr(finding, "severity", "medium") or "medium").lower()
            rule_id = f"skill/{category}"
            level = _LEVEL_BY_SEVERITY.get(severity, "warning")
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append(_rule(rule_id, finding, severity, level))
            results.append(_result(rule_id, path, finding, severity, level, trust))

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-bom skills",
                        "informationUri": "https://github.com/msaad00/agent-bom",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "report_type": "skills_scan",
                    "schema_version": str(schema_version),
                },
            }
        ],
    }


def _rule(rule_id: str, finding: Any, severity: str, level: str) -> dict[str, Any]:
    title = _text("title", getattr(finding, "title", None), fallback=rule_id)
    detail = _text("description", getattr(finding, "detail", None), fallback=title)
    return {
        "id": rule_id,
        "shortDescription": {"text": title},
        "fullDescription": {"text": detail},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(severity, "4.0"),
            "category": str(getattr(finding, "category", "")),
        },
    }


def _result(rule_id: str, path: str, finding: Any, severity: str, level: str, trust: dict[str, Any]) -> dict[str, Any]:
    title = _text("title", getattr(finding, "title", None), fallback=rule_id)
    fingerprint = _fingerprint(path, finding)
    line = _positive_int(getattr(finding, "source_line", None), default=1)
    column = _positive_int(getattr(finding, "source_column", None), default=1)
    return {
        "ruleId": rule_id,
        "level": level,
        "kind": "fail" if level in {"error", "warning"} else "informational",
        "message": {"text": title},
        "fingerprints": {"agent-bom/skills/v1": fingerprint},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "startColumn": column},
                }
            }
        ],
        "properties": {
            "severity": severity,
            "category": str(getattr(finding, "category", "")),
            "context": str(getattr(finding, "context", "")),
            "evidence_source": str(getattr(finding, "evidence_source", "static_config")),
            "confidence": str(getattr(finding, "confidence", "medium")),
            "detail": _property(getattr(finding, "detail", "")),
            "recommendation": _property(getattr(finding, "recommendation", "")),
            "trust": trust,
        },
    }


def _trust_properties(file_report: Any) -> dict[str, str]:
    trust = getattr(file_report, "trust", None)
    return {
        key: value
        for key, value in {
            "verdict": _enum_value(getattr(trust, "verdict", None)),
            "content_verdict": _enum_value(getattr(trust, "content_verdict", None)),
            "provenance_verdict": _enum_value(getattr(trust, "provenance_verdict", None)),
            "review_verdict": _enum_value(getattr(trust, "review_verdict", None)),
            "overall_recommendation": _enum_value(getattr(trust, "review_verdict", None)),
            "confidence": _enum_value(getattr(trust, "confidence", None)),
        }.items()
        if value
    }


def _fingerprint(path: str, finding: Any) -> str:
    material = "|".join(
        [
            path,
            str(getattr(finding, "category", "")),
            str(getattr(finding, "severity", "")),
            str(getattr(finding, "title", "")),
            str(getattr(finding, "detail", "")),
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _relative_path(path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            return p.name
    return path


def _text(field_name: str, value: Any, *, fallback: str = "") -> str:
    sanitized = sanitize_sensitive_payload(str(value or ""), key=field_name, max_str_len=1000)
    redacted = redact_for_persistence({field_name: sanitized}, EvidenceTier.SAFE_TO_STORE).get(field_name)
    return str(redacted if redacted is not None else fallback)


def _property(value: Any) -> Any:
    sanitized = sanitize_sensitive_payload(value, max_str_len=1000)
    if isinstance(sanitized, str):
        return _text("detail", sanitized)
    return redact_for_persistence({"details": sanitized}, EvidenceTier.SAFE_TO_STORE).get("details")


def _enum_value(value: Any) -> str | None:
    raw = getattr(value, "value", value)
    if raw is None:
        return None
    return str(raw)


def _positive_int(value: Any, *, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return parsed if parsed > 0 else default
