"""Validated, tool-neutral SARIF normalization.

The scanner and external-evidence lanes deliberately share this structural
boundary.  Adapters may project the normalized records into different product
models, but they must not reinterpret the source document independently.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class SarifValidationError(ValueError):
    """Raised when a payload cannot be treated as a SARIF document."""


@dataclass(frozen=True)
class SarifLocation:
    """The first physical source location attached to a SARIF result."""

    uri: str
    start_line: int = 0
    end_line: int = 0
    start_column: int = 0
    end_column: int = 0
    snippet: str | None = None


@dataclass(frozen=True)
class NormalizedSarifResult:
    """A result with its run- and rule-level provenance resolved."""

    tool_name: str
    rule_id: str
    message: str
    level: str | None
    security_severity: float | None
    rule_tags: tuple[str, ...] = ()
    rule_url: str | None = None
    rule_short_description: str = ""
    rule_full_description: str = ""
    location: SarifLocation | None = None
    fingerprints: dict[str, str] = field(default_factory=dict)
    partial_fingerprints: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class NormalizedSarifDocument:
    """Normalized results plus stable document-level accounting."""

    results: tuple[NormalizedSarifResult, ...]
    rules_loaded: int
    files_scanned: int
    tool_names: tuple[str, ...]


def _mapping(value: object, field_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SarifValidationError(f"SARIF {field_name} must be an object")
    return value


def _list(value: object, field_name: str) -> list[Any]:
    if not isinstance(value, list):
        raise SarifValidationError(f"SARIF {field_name} must be an array")
    return value


def _text(message: object) -> str:
    if message is None:
        return ""
    message_obj = _mapping(message, "message")
    text = message_obj.get("text")
    markdown = message_obj.get("markdown")
    if text is not None and not isinstance(text, str):
        raise SarifValidationError("SARIF message.text must be a string")
    if markdown is not None and not isinstance(markdown, str):
        raise SarifValidationError("SARIF message.markdown must be a string")
    return str(text or markdown or "")


def _properties(value: object, field_name: str) -> dict[str, Any]:
    if value is None:
        return {}
    return _mapping(value, field_name)


def _security_severity(result: dict[str, Any], rule: dict[str, Any]) -> float | None:
    result_properties = _properties(result.get("properties"), "result.properties")
    rule_properties = _properties(rule.get("properties"), "rule.properties")
    raw = result_properties.get("security-severity")
    if raw is None:
        raw = rule_properties.get("security-severity")
    if raw is None:
        return None
    try:
        score = float(raw)
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _string_map(value: object, field_name: str) -> dict[str, str]:
    if value is None:
        return {}
    raw = _mapping(value, field_name)
    return {str(key): item for key, item in raw.items() if isinstance(item, str)}


def _location(result: dict[str, Any]) -> SarifLocation | None:
    raw_locations = result.get("locations")
    if raw_locations is None:
        return None
    locations = _list(raw_locations, "result.locations")
    if not locations:
        return None
    first = _mapping(locations[0], "result.locations[]")
    physical_raw = first.get("physicalLocation")
    if physical_raw is None:
        return None
    physical = _mapping(physical_raw, "physicalLocation")
    artifact = _properties(physical.get("artifactLocation"), "artifactLocation")
    uri_raw = artifact.get("uri")
    if uri_raw is not None and not isinstance(uri_raw, str):
        raise SarifValidationError("SARIF artifactLocation.uri must be a string")
    uri = str(uri_raw or "")
    if not uri:
        return None

    region = _properties(physical.get("region"), "region")
    snippet_obj = _properties(region.get("snippet"), "region.snippet")
    snippet_raw = snippet_obj.get("text")
    if snippet_raw is not None and not isinstance(snippet_raw, str):
        raise SarifValidationError("SARIF region.snippet.text must be a string")

    def integer(name: str, default: int = 0) -> int:
        value = region.get(name, default)
        return value if isinstance(value, int) and not isinstance(value, bool) else default

    start_line = integer("startLine")
    return SarifLocation(
        uri=uri,
        start_line=start_line,
        end_line=integer("endLine", start_line),
        start_column=integer("startColumn"),
        end_column=integer("endColumn"),
        snippet=snippet_raw,
    )


def _description(rule: dict[str, Any], name: str) -> str:
    value = rule.get(name)
    return _text(value) if value is not None else ""


def normalize_sarif_document(payload: object) -> NormalizedSarifDocument:
    """Validate and normalize one SARIF 2.x document.

    A structurally invalid payload raises :class:`SarifValidationError`; a
    valid document with zero results produces an intentionally empty result.
    """

    sarif = _mapping(payload, "document")
    version = sarif.get("version")
    schema = sarif.get("$schema")
    version_is_sarif = isinstance(version, str) and version.startswith("2.")
    schema_is_sarif = isinstance(schema, str) and "sarif" in schema.lower()
    if not version_is_sarif and not schema_is_sarif:
        raise SarifValidationError("payload is not a SARIF 2.x document")

    runs = _list(sarif.get("runs"), "runs")
    normalized: list[NormalizedSarifResult] = []
    files: set[str] = set()
    tool_names: list[str] = []
    rules_loaded = 0

    for run_index, raw_run in enumerate(runs):
        run = _mapping(raw_run, f"runs[{run_index}]")
        tool = _mapping(run.get("tool"), f"runs[{run_index}].tool")
        driver = _mapping(tool.get("driver"), f"runs[{run_index}].tool.driver")
        tool_name = driver.get("name")
        if not isinstance(tool_name, str) or not tool_name.strip():
            raise SarifValidationError(f"SARIF runs[{run_index}] tool driver name is required")
        tool_name = tool_name.strip()
        if tool_name not in tool_names:
            tool_names.append(tool_name)

        raw_rules = driver.get("rules", [])
        rules = _list(raw_rules, f"runs[{run_index}].tool.driver.rules")
        rule_index: dict[str, dict[str, Any]] = {}
        for rule_offset, raw_rule in enumerate(rules):
            rule = _mapping(raw_rule, f"runs[{run_index}].tool.driver.rules[{rule_offset}]")
            rule_id = rule.get("id")
            if isinstance(rule_id, str) and rule_id:
                rule_index[rule_id] = rule
        rules_loaded += len(rule_index)

        results = _list(run.get("results", []), f"runs[{run_index}].results")
        for result_offset, raw_result in enumerate(results):
            result = _mapping(raw_result, f"runs[{run_index}].results[{result_offset}]")
            raw_rule_id = result.get("ruleId")
            if raw_rule_id is not None and not isinstance(raw_rule_id, str):
                raise SarifValidationError("SARIF result.ruleId must be a string")
            rule_id = str(raw_rule_id or "")
            rule = rule_index.get(rule_id, {})
            rule_properties = _properties(rule.get("properties"), "rule.properties")
            raw_tags = rule_properties.get("tags", [])
            tags = _list(raw_tags, "rule.properties.tags")
            rule_tags = tuple(tag for tag in tags if isinstance(tag, str))
            level = result.get("level")
            if level is not None and not isinstance(level, str):
                raise SarifValidationError("SARIF result.level must be a string")
            location = _location(result)
            if location is not None:
                files.add(location.uri)

            normalized.append(
                NormalizedSarifResult(
                    tool_name=tool_name,
                    rule_id=rule_id,
                    message=_text(result.get("message")),
                    level=level,
                    security_severity=_security_severity(result, rule),
                    rule_tags=rule_tags,
                    rule_url=str(rule.get("helpUri")) if isinstance(rule.get("helpUri"), str) else None,
                    rule_short_description=_description(rule, "shortDescription"),
                    rule_full_description=_description(rule, "fullDescription"),
                    location=location,
                    fingerprints=_string_map(result.get("fingerprints"), "result.fingerprints"),
                    partial_fingerprints=_string_map(result.get("partialFingerprints"), "result.partialFingerprints"),
                )
            )

    return NormalizedSarifDocument(
        results=tuple(normalized),
        rules_loaded=rules_loaded,
        files_scanned=len(files),
        tool_names=tuple(tool_names),
    )
