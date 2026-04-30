#!/usr/bin/env python3
"""Convert ``agent-bom code --format json`` output to SARIF."""

from __future__ import annotations

import hashlib
import importlib.metadata
import json
import re
import sys
from pathlib import Path
from typing import Any

_LEVELS = {
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
_CREDENTIAL_ASSIGNMENT = re.compile(
    r"(?i)\b(token|secret|password|passwd|api[_-]?key|access[_-]?key|session[_-]?token)\s*=\s*[^\s,;]+"
)


def _agent_bom_version() -> str:
    try:
        return importlib.metadata.version("agent-bom")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0"


def _safe_text(value: object, *, max_len: int = 500) -> str:
    text = str(value or "").replace("\x00", "").strip()
    text = _CREDENTIAL_ASSIGNMENT.sub(lambda match: f"{match.group(1)}=<redacted>", text)
    return text[:max_len]


def _relative_path(value: object) -> str:
    text = _safe_text(value, max_len=300).replace("\\", "/").lstrip("/")
    return text or "unknown"


def _line_number(value: object) -> int:
    try:
        line = int(str(value or 1))
    except (TypeError, ValueError):
        return 1
    return max(line, 1)


def _add_rule(rules: dict[str, dict[str, Any]], rule_id: str, title: str, severity: str, category: str) -> None:
    if rule_id in rules:
        return
    sev = severity.lower()
    rules[rule_id] = {
        "id": rule_id,
        "shortDescription": {"text": _safe_text(title, max_len=120) or rule_id},
        "defaultConfiguration": {"level": _LEVELS.get(sev, "warning")},
        "properties": {
            "security-severity": _SECURITY_SEVERITY.get(sev, "4.0"),
            "category": _safe_text(category, max_len=80),
        },
    }


def _result(rule_id: str, level: str, message: str, file_path: str, line: int, fingerprint_input: str) -> dict[str, Any]:
    return {
        "ruleId": rule_id,
        "level": level,
        "kind": "fail" if level in {"error", "warning"} else "informational",
        "message": {"text": _safe_text(message, max_len=1000)},
        "fingerprints": {"agent-bom-code/v1": hashlib.sha256(fingerprint_input.encode("utf-8")).hexdigest()},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }
        ],
    }


def convert(data: dict[str, Any]) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in data.get("flow_findings") or []:
        if not isinstance(finding, dict):
            continue
        category = _safe_text(finding.get("category") or "flow")
        rule_id = f"agent-bom-code-flow/{category}"
        title = _safe_text(finding.get("title") or category.replace("_", " ").title())
        detail = _safe_text(finding.get("detail") or title, max_len=1000)
        file_path = _relative_path(finding.get("file"))
        line = _line_number(finding.get("line"))
        _add_rule(rules, rule_id, title, "medium", category)
        results.append(_result(rule_id, "warning", detail, file_path, line, f"{rule_id}:{file_path}:{line}:{detail}"))

    ai_components = data.get("ai_components") or {}
    if isinstance(ai_components, dict):
        candidates: list[dict[str, Any]] = []
        for key in ("components", "deprecated_models", "api_keys", "shadow_ai"):
            values = ai_components.get(key) or []
            if isinstance(values, list):
                candidates.extend(item for item in values if isinstance(item, dict))
        for component in candidates:
            severity = _safe_text(component.get("severity") or "info").lower()
            component_type = _safe_text(component.get("component_type") or component.get("kind") or "component")
            if severity == "info" and component_type not in {"api_key", "deprecated_model"}:
                continue
            name = "[REDACTED]" if component_type == "api_key" else _safe_text(component.get("name") or component_type, max_len=120)
            rule_id = f"agent-bom-ai-component/{component_type}"
            title = f"{component_type.replace('_', ' ').title()}: {name}"
            file_path = _relative_path(component.get("file_path") or component.get("file"))
            line = _line_number(component.get("line_number") or component.get("line"))
            level = _LEVELS.get(severity, "warning")
            message = _safe_text(component.get("description") or title, max_len=1000)
            _add_rule(rules, rule_id, title, severity, component_type)
            results.append(_result(rule_id, level, message, file_path, line, f"{rule_id}:{file_path}:{line}:{name}"))

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-bom code",
                        "version": _agent_bom_version(),
                        "informationUri": "https://github.com/msaad00/agent-bom",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def main(argv: list[str] | None = None) -> int:
    args = list(argv or sys.argv[1:])
    if len(args) != 2:
        print("usage: code_scan_json_to_sarif.py INPUT.json OUTPUT.sarif", file=sys.stderr)
        return 2
    input_path = Path(args[0])
    output_path = Path(args[1])
    data = json.loads(input_path.read_text(encoding="utf-8"))
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(convert(data), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
