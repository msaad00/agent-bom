"""Enforce the OCSF boundary documented in ``docs/OCSF_BOUNDARY.md``.

OCSF is an optional SIEM wire protocol. Core modules
(scan, enrichment, parsers, cli, cloud, skills, analyzers, api,
dashboard, db, ingestion) must not import from ``agent_bom.siem.ocsf``
or ``agent_bom.output.ocsf``. The graph layer is allowed to import
``agent_bom.graph.ocsf`` because that file is a thin entity→OCSF-id
mapping table the graph uses as reserved seats for SIEM export;
nothing in core logic branches on those IDs.

If this test fails, either:
1. Move the OCSF-using code behind a boundary module (``siem/``,
   ``output/ocsf.py``), or
2. Update ``docs/OCSF_BOUNDARY.md`` and ``_ALLOWED_OCSF_CONSUMERS``
   below with an explicit, reviewed exception.
"""

from __future__ import annotations

import ast
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_SRC_ROOT = _REPO_ROOT / "src" / "agent_bom"

# Files that may import the emission-layer OCSF modules. Everything else
# under src/agent_bom must not.
_ALLOWED_OCSF_CONSUMERS = {
    # siem/ is the SIEM wire boundary — may import freely.
    "siem/__init__.py",
    "siem/ocsf.py",
    "siem/splunk.py",
    "siem/sentinel.py",
    "siem/chronicle.py",
    "siem/security_lake.py",
    "siem/delta_stream.py",
    # output/ocsf.py is the MCP tool's OCSF serializer.
    "output/ocsf.py",
}

_OCSF_EMISSION_MODULES = {"agent_bom.output.ocsf", "agent_bom.siem.ocsf"}


def _package_for(relative_path: str) -> list[str]:
    parent = Path(relative_path).parent
    return ["agent_bom", *(() if str(parent) == "." else parent.parts)]


def _resolve_from_import(node: ast.ImportFrom, relative_path: str) -> str:
    if node.level == 0:
        return node.module or ""
    package = _package_for(relative_path)
    keep = max(0, len(package) - (node.level - 1))
    base = package[:keep]
    if node.module:
        base.extend(node.module.split("."))
    return ".".join(base)


def _literal_module_name(call: ast.Call) -> str | None:
    if not call.args or not isinstance(call.args[0], ast.Constant) or not isinstance(call.args[0].value, str):
        return None
    if isinstance(call.func, ast.Name) and call.func.id in {"__import__", "import_module"}:
        return call.args[0].value
    if isinstance(call.func, ast.Attribute) and call.func.attr == "import_module":
        return call.args[0].value
    return None


def _ocsf_imports(source: str, relative_path: str) -> list[tuple[int, str]]:
    offenders: list[tuple[int, str]] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in _OCSF_EMISSION_MODULES:
                    offenders.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            base = _resolve_from_import(node, relative_path)
            if base in _OCSF_EMISSION_MODULES:
                offenders.append((node.lineno, base))
            for alias in node.names:
                imported = f"{base}.{alias.name}" if base else alias.name
                if imported in _OCSF_EMISSION_MODULES:
                    offenders.append((node.lineno, imported))
        elif isinstance(node, ast.Call):
            imported = _literal_module_name(node)
            if imported in _OCSF_EMISSION_MODULES:
                offenders.append((node.lineno, imported))
    return sorted(set(offenders))


def test_no_core_module_imports_ocsf_emission_layer():
    offenders: list[str] = []
    for path in _SRC_ROOT.rglob("*.py"):
        rel = path.relative_to(_SRC_ROOT).as_posix()
        if rel in _ALLOWED_OCSF_CONSUMERS:
            continue
        source = path.read_text(encoding="utf-8")
        offenders.extend(f"{rel}:{line} ({module})" for line, module in _ocsf_imports(source, rel))
    assert not offenders, (
        "OCSF boundary violation — these core modules import the "
        "OCSF emission layer. See docs/OCSF_BOUNDARY.md:\n  - " + "\n  - ".join(sorted(offenders))
    )


def test_ocsf_boundary_guard_covers_import_shapes() -> None:
    cases = {
        "import agent_bom.siem.ocsf": "agent_bom.siem.ocsf",
        "from agent_bom.siem.ocsf import to_ocsf_batch": "agent_bom.siem.ocsf",
        "from agent_bom.siem import ocsf": "agent_bom.siem.ocsf",
        "from ..siem import ocsf": "agent_bom.siem.ocsf",
        'import_module("agent_bom.output.ocsf")': "agent_bom.output.ocsf",
        'importlib.import_module("agent_bom.siem.ocsf")': "agent_bom.siem.ocsf",
        '__import__("agent_bom.output.ocsf")': "agent_bom.output.ocsf",
    }
    for source, expected in cases.items():
        assert _ocsf_imports(source, "api/example.py") == [(1, expected)]


def test_graph_ocsf_map_is_thin_mapping_only():
    """``graph/ocsf.py`` may stay in core, but must remain a pure
    mapping table — no SIEM/event construction, no network I/O, no
    serialization. If this file grows logic, it should move to an
    emission-layer module."""

    text = (_SRC_ROOT / "graph" / "ocsf.py").read_text(encoding="utf-8")
    for forbidden in ("import requests", "import urllib", "socket", "json.dumps", "to_ocsf_event"):
        assert forbidden not in text, (
            f"graph/ocsf.py must stay a thin mapping — found '{forbidden}'. Move emission logic to siem/ocsf.py or output/ocsf.py."
        )
