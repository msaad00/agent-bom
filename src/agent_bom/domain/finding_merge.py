"""Fold external code-scanner results onto native findings at the same location."""

from __future__ import annotations

from agent_bom.finding import Finding, FindingSource, FindingType


def _normalized_path(value: object) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if text.startswith("file://"):
        text = text[len("file://") :]
    while text.startswith("./"):
        text = text[2:]
    return text.lstrip("/")


def _paths_match(left: str, right: str) -> bool:
    if not left or not right:
        return False
    return left == right or left.endswith("/" + right) or right.endswith("/" + left)


def _native_code_anchor(finding: Finding) -> tuple[str, int | None, str] | None:
    """Return ``(path, line, rule_id)`` for a native code-level finding, else None."""
    if finding.source is FindingSource.EXTERNAL:
        return None
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    if finding.finding_type is FindingType.SAST:
        path = _normalized_path(evidence.get("file") or finding.asset.location)
        line = evidence.get("line")
        return (path, line if isinstance(line, int) else None, str(evidence.get("rule_id") or "")) if path else None
    # Native rule-engine results travel as per-file ``sast`` packages.
    if evidence.get("ecosystem") == "sast" and evidence.get("package_name"):
        return (_normalized_path(evidence["package_name"]), None, str(finding.cve_id or ""))
    return None


def merge_external_code_findings(findings: list[Finding]) -> list[Finding]:
    """Collapse external code results onto the native finding at the same place.

    An external SAST result merges into a native code finding when the file
    matches and either the line matches with an overlapping CWE (or the same
    rule id), or a native rule-engine result carries the same rule id for that
    file. The native finding keeps its source and gains both provenance labels;
    unmatched external results stay as EXTERNAL SAST findings.
    """
    anchors = [(finding, anchor) for finding in findings if (anchor := _native_code_anchor(finding)) is not None]
    if not anchors:
        return findings

    merged: list[Finding] = []
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        if finding.source is not FindingSource.EXTERNAL or finding.finding_type is not FindingType.SAST:
            merged.append(finding)
            continue
        path = _normalized_path(evidence.get("file") or finding.asset.location)
        line = evidence.get("line")
        rule_id = str(evidence.get("rule_id") or "")
        cwes = set(finding.cwe_ids)
        target = None
        for native, (native_path, native_line, native_rule) in anchors:
            if not _paths_match(path, native_path):
                continue
            same_rule = bool(rule_id) and rule_id == native_rule
            if native_line is None:
                if same_rule:
                    target = native
                    break
                continue
            if native_line == line and (same_rule or cwes & set(native.cwe_ids)):
                target = native
                break
        if target is None:
            merged.append(finding)
            continue
        labels = target.sources or ["native"]
        target.sources = list(dict.fromkeys([*labels, *(finding.sources or ["external"])]))
        match = {"tool": evidence.get("external_tool"), "rule_id": rule_id, "line": line}
        matches = target.evidence.setdefault("external_matches", [])
        if match not in matches:
            matches.append(match)
    return merged
