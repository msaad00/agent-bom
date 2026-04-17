#!/usr/bin/env python3
"""CI enforcement: verify counts across README/docs/listings match source of truth.

Run: python scripts/check-counts.py
Exit 0 = all consistent. Exit 1 = drift detected.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ERRORS: list[str] = []


def _count_in_file(path: Path, pattern: str) -> list[tuple[int, str]]:
    """Return (line_number, line_text) for each match."""
    matches = []
    try:
        for i, line in enumerate(path.read_text().splitlines(), 1):
            if re.search(pattern, line):
                matches.append((i, line.strip()))
    except FileNotFoundError:
        pass
    return matches


def _check(label: str, expected: str, files: list[str], pattern: str, exclude_pattern: str = ""):
    """Check that `pattern` matches `expected` in all files. Report drift."""
    for fpath in files:
        p = ROOT / fpath
        if not p.exists():
            continue
        for lineno, line in _count_in_file(p, pattern):
            if exclude_pattern and re.search(exclude_pattern, line):
                continue
            # Extract the number from the line
            nums = re.findall(r"\d+", re.search(pattern, line).group(0)) if re.search(pattern, line) else []
            if nums and nums[0] != expected:
                ERRORS.append(f"  {fpath}:{lineno} — {label}: found {nums[0]}, expected {expected}")


# ── Source of truth: count from actual code ────────────────────────────────

# MCP tools: count @mcp.tool decorators
mcp_server = ROOT / "src/agent_bom/mcp_server.py"
mcp_tool_count = mcp_server.read_text().count("@mcp.tool") if mcp_server.exists() else 0

# Runtime detectors: count class definitions in detectors.py
detectors = ROOT / "src/agent_bom/runtime/detectors.py"
detector_classes = (
    len(re.findall(r"^class \w+(?:Detector|Analyzer|Inspector|Correlator)\b", detectors.read_text(), re.MULTILINE))
    if detectors.exists()
    else 0
)

# Dashboard pages
# Count subdirectory pages + root page
_sub_pages = len(list((ROOT / "ui/app").glob("*/page.tsx"))) if (ROOT / "ui/app").exists() else 0
_root_page = 1 if (ROOT / "ui/app/page.tsx").exists() else 0
pages = _sub_pages + _root_page

# IaC rules
iac_rules = 0
for iac_file in (ROOT / "src/agent_bom/iac").glob("*.py"):
    content = iac_file.read_text()
    iac_rules += len(re.findall(r'rule_id="[A-Z]+-(?:SEC-)?\d+', content))

# Output formats
output_formats = (
    len([f for f in (ROOT / "src/agent_bom/output").glob("*.py") if f.name not in ("__init__.py", "__pycache__")])
    if (ROOT / "src/agent_bom/output").exists()
    else 0
)

print("Source of truth from code:")
print(f"  MCP tools:       {mcp_tool_count}")
print(f"  Detectors:       {detector_classes}")
print(f"  Dashboard pages: {pages}")
print(f"  IaC rules:       {iac_rules}")
print(f"  Output formats:  {output_formats}")
print()

# ── Check surfaces ─────────────────────────────────────────────────────────

SURFACES = [
    "README.md",
    "DOCKER_HUB_README.md",
    "docs/ARCHITECTURE.md",
    "docs/archive/STRATEGIC_AUDIT_2026_03.md",
    "docs/archive/AUDIT.md",
    "pyproject.toml",
    "action.yml",
]

# Check MCP tools count
_check("MCP tools", str(mcp_tool_count), SURFACES, r"\d+ MCP (?:server )?tools")

# Check detector count
_check("Detectors", str(detector_classes), SURFACES, r"\d+ (?:behavioral )?detectors", exclude_pattern=r"17 behavioral")

# Check dashboard pages
_check("Pages", str(pages), SURFACES, r"\d+-page")

# ── Version consistency ────────────────────────────────────────────────────

pyproject = ROOT / "pyproject.toml"
version_match = re.search(r'version\s*=\s*"([^"]+)"', pyproject.read_text()) if pyproject.exists() else None
if version_match:
    version = version_match.group(1)
    # Check skills
    for skill in (ROOT / "integrations/openclaw").rglob("SKILL.md"):
        for lineno, line in _count_in_file(skill, r"version:\s"):
            skill_ver = re.search(r"version:\s*(\S+)", line)
            if skill_ver and skill_ver.group(1) != version:
                ERRORS.append(f"  {skill.relative_to(ROOT)}:{lineno} — version: {skill_ver.group(1)}, expected {version}")

# ── Report ─────────────────────────────────────────────────────────────────

if ERRORS:
    print(f"❌ {len(ERRORS)} count/version drift(s) found:\n")
    for e in ERRORS:
        print(e)
    print("\nFix these before release. Run: python scripts/check-counts.py")
    sys.exit(1)
else:
    print("✅ All counts and versions consistent.")
    sys.exit(0)
