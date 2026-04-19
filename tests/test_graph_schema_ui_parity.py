from __future__ import annotations

import re
from pathlib import Path

from agent_bom.graph import FINDING_ENTITY_TYPES, EntityType, GraphLayout, RelationshipType
from agent_bom.graph.container import GraphFilterOptions
from agent_bom.graph.severity import SEVERITY_RANK, SEVERITY_RISK_SCORE, SEVERITY_TO_OCSF, OCSFSeverity

ROOT = Path(__file__).resolve().parent.parent
TS_GRAPH_SCHEMA = ROOT / "ui" / "lib" / "graph-schema.ts"
TS_SOURCE = TS_GRAPH_SCHEMA.read_text(encoding="utf-8")


def _block_after(marker: str, opener: str, closer: str) -> str:
    start = TS_SOURCE.index(marker)
    open_idx = TS_SOURCE.index(opener, start)
    depth = 0
    for idx in range(open_idx, len(TS_SOURCE)):
        char = TS_SOURCE[idx]
        if char == opener:
            depth += 1
        elif char == closer:
            depth -= 1
            if depth == 0:
                return TS_SOURCE[open_idx + 1 : idx]
    raise AssertionError(f"Could not parse block for {marker}")


def _ts_enum_values(name: str) -> set[str]:
    body = _block_after(f"export enum {name}", "{", "}")
    return {value for _key, value in re.findall(r"(\w+)\s*=\s*\"([^\"]+)\"", body)}


def _ts_enum_mapping(name: str) -> dict[str, int]:
    body = _block_after(f"export enum {name}", "{", "}")
    return {key: int(value) for key, value in re.findall(r"(\w+)\s*=\s*(\d+)", body)}


def _ts_object_mapping(name: str, *, enum_refs: dict[str, int] | None = None) -> dict[str, int | float]:
    body = _block_after(f"export const {name}", "{", "}")
    mapping: dict[str, int | float] = {}
    for raw_key, raw_value in re.findall(r"^\s*([A-Za-z_]+):\s*([^,\n]+)", body, re.MULTILINE):
        value = raw_value.strip()
        if enum_refs and value.startswith("OCSFSeverity."):
            mapping[raw_key] = enum_refs[value.split(".", 1)[1]]
        elif re.fullmatch(r"\d+", value):
            mapping[raw_key] = int(value)
        elif re.fullmatch(r"\d+\.\d+", value):
            mapping[raw_key] = float(value)
    return mapping


def _ts_default_filters(enum_refs: dict[str, str]) -> dict[str, object]:
    function_start = TS_SOURCE.index("export function defaultFilters()")
    return_start = TS_SOURCE.index("return {", function_start)
    open_idx = TS_SOURCE.index("{", return_start)
    depth = 0
    close_idx = open_idx
    for idx in range(open_idx, len(TS_SOURCE)):
        char = TS_SOURCE[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                close_idx = idx
                break
    body = TS_SOURCE[open_idx + 1 : close_idx]
    defaults: dict[str, object] = {}
    for raw_key, raw_value in re.findall(r"^\s*([A-Za-z]+):\s*([^,\n]+)", body, re.MULTILINE):
        value = raw_value.strip()
        if value in {"false", "true"}:
            defaults[raw_key] = value == "true"
        elif value == '""':
            defaults[raw_key] = ""
        elif value == "new Set()":
            defaults[raw_key] = set()
        elif re.fullmatch(r"\d+", value):
            defaults[raw_key] = int(value)
        elif value.startswith("GraphLayout."):
            defaults[raw_key] = enum_refs[value.split(".", 1)[1]]
    return defaults


def test_ui_entity_types_match_python_graph_schema():
    assert _ts_enum_values("EntityType") == {entity.value for entity in EntityType}


def test_ui_relationship_types_match_python_graph_schema():
    assert _ts_enum_values("RelationshipType") == {relationship.value for relationship in RelationshipType}


def test_ui_graph_layouts_match_python_graph_schema():
    assert _ts_enum_values("GraphLayout") == {layout.value for layout in GraphLayout}


def test_ui_severity_constants_match_python_graph_schema():
    ts_ocsf = _ts_enum_mapping("OCSFSeverity")
    assert ts_ocsf == {severity.name: int(severity.value) for severity in OCSFSeverity}
    assert _ts_object_mapping("SEVERITY_TO_OCSF", enum_refs=ts_ocsf) == {key: int(value) for key, value in SEVERITY_TO_OCSF.items()}
    assert _ts_object_mapping("SEVERITY_RANK") == SEVERITY_RANK
    assert _ts_object_mapping("SEVERITY_RISK_SCORE") == SEVERITY_RISK_SCORE


def test_ui_finding_entity_types_match_python_graph_schema():
    body = _block_after("export const FINDING_ENTITY_TYPES", "[", "]")
    ts_findings = {match.split(".", 1)[1].strip() for match in re.findall(r"EntityType\.\w+", body)}
    assert ts_findings == {entity.name for entity in FINDING_ENTITY_TYPES}


def test_ui_default_filters_match_python_graph_schema():
    layout_block = _block_after("export enum GraphLayout", "{", "}")
    ts_layout_names = {name: value for name, value in re.findall(r"(\w+)\s*=\s*\"([^\"]+)\"", layout_block)}
    defaults = GraphFilterOptions()
    assert _ts_default_filters(ts_layout_names) == {
        "maxDepth": defaults.max_depth,
        "maxHops": defaults.max_hops,
        "minSeverity": defaults.min_severity,
        "entityTypes": set(),
        "relationshipTypes": set(),
        "staticOnly": defaults.static_only,
        "dynamicOnly": defaults.dynamic_only,
        "includeIds": set(),
        "excludeIds": set(),
        "layout": defaults.layout,
    }
