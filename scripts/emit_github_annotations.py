#!/usr/bin/env python3
"""Emit GitHub Actions annotations from agent-bom result files."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Iterable


def _escape_data(value: object) -> str:
    text = str(value or "")
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_property(value: object) -> str:
    return _escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _annotation(
    *,
    level: str,
    path: str,
    title: str,
    message: str,
    line: int | None = None,
    col: int | None = None,
) -> str:
    properties = [f"file={_escape_property(path)}"]
    if line is not None and line > 0:
        properties.append(f"line={line}")
    if col is not None and col > 0:
        properties.append(f"col={col}")
    if title:
        properties.append(f"title={_escape_property(title)}")
    return f"::{level} {','.join(properties)}::{_escape_data(message)}"


def _as_int(value: object) -> int | None:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _skills_json_annotations(data: dict[str, Any]) -> Iterable[str]:
    for file_report in data.get("files", []):
        if not isinstance(file_report, dict):
            continue
        fallback_path = str(file_report.get("path") or "")
        audit = file_report.get("audit")
        if not isinstance(audit, dict):
            continue
        for finding in audit.get("findings", []):
            if not isinstance(finding, dict):
                continue
            path = str(finding.get("source_file") or fallback_path)
            if not path:
                continue
            severity = str(finding.get("severity") or "unknown").upper()
            category = str(finding.get("category") or "skill")
            title = str(finding.get("title") or "agent-bom skill finding")
            detail = str(finding.get("detail") or title)
            yield _annotation(
                level="warning",
                path=path,
                line=_as_int(finding.get("source_line")),
                col=_as_int(finding.get("source_column")),
                title=f"agent-bom {severity} {category}",
                message=f"{title}: {detail}",
            )


def _sarif_annotations(data: dict[str, Any]) -> Iterable[str]:
    run = (data.get("runs") or [{}])[0]
    if not isinstance(run, dict):
        return
    rules = {str(rule.get("id")): rule for rule in run.get("tool", {}).get("driver", {}).get("rules", []) if isinstance(rule, dict)}
    for result in run.get("results", []):
        if not isinstance(result, dict):
            continue
        location = (result.get("locations") or [{}])[0]
        physical = location.get("physicalLocation", {}) if isinstance(location, dict) else {}
        artifact = physical.get("artifactLocation", {}) if isinstance(physical, dict) else {}
        region = physical.get("region", {}) if isinstance(physical, dict) else {}
        path = str(artifact.get("uri") or "")
        if not path:
            continue
        rule_id = str(result.get("ruleId") or "agent-bom")
        rule = rules.get(rule_id, {})
        rule_name = rule.get("name") if isinstance(rule, dict) else None
        message = str(result.get("message", {}).get("text") or rule_name or rule_id)
        yield _annotation(
            level="warning",
            path=path,
            line=_as_int(region.get("startLine")) if isinstance(region, dict) else None,
            col=_as_int(region.get("startColumn")) if isinstance(region, dict) else None,
            title=f"agent-bom {rule_id}",
            message=message,
        )


def emit_annotations(path: Path, *, max_annotations: int) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return []
    if "runs" in data:
        annotations = list(_sarif_annotations(data))
    elif data.get("report_type") == "skills_scan":
        annotations = list(_skills_json_annotations(data))
    else:
        annotations = []
    if max_annotations >= 0:
        annotations = annotations[:max_annotations]
    return annotations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("result_file", type=Path)
    parser.add_argument("--max", type=int, default=50, help="Maximum annotations to emit; -1 emits all.")
    args = parser.parse_args(argv)
    try:
        for annotation in emit_annotations(args.result_file, max_annotations=args.max):
            print(annotation)
    except Exception as exc:
        print(f"::warning::agent-bom annotation emission failed: {_escape_data(exc)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
