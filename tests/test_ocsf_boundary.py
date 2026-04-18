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

import re
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
    # output/ocsf.py is the MCP tool's OCSF serializer.
    "output/ocsf.py",
}

_OCSF_EMISSION_IMPORT = re.compile(
    r"from\s+agent_bom\.(siem\.ocsf|output\.ocsf)\s+import"
    r"|import\s+agent_bom\.(siem\.ocsf|output\.ocsf)"
)


def test_no_core_module_imports_ocsf_emission_layer():
    offenders: list[str] = []
    for path in _SRC_ROOT.rglob("*.py"):
        rel = path.relative_to(_SRC_ROOT).as_posix()
        if rel in _ALLOWED_OCSF_CONSUMERS:
            continue
        text = path.read_text(encoding="utf-8")
        if _OCSF_EMISSION_IMPORT.search(text):
            offenders.append(rel)
    assert not offenders, (
        "OCSF boundary violation — these core modules import the "
        "OCSF emission layer. See docs/OCSF_BOUNDARY.md:\n  - " + "\n  - ".join(sorted(offenders))
    )


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
