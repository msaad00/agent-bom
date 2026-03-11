"""Delta scanning — diff current scan against a baseline, report only new findings.

Usage:
    agent-bom scan --baseline-file scan-main.json --delta
    agent-bom scan --delta   # auto-loads last saved baseline from ~/.agent-bom/baseline.json

The delta key for deduplication is (vulnerability_id, package_name, package_version).
Exit code is based on *new* findings only; pre-existing findings are suppressed.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)

# Default path for auto-saved baselines
_DEFAULT_BASELINE_PATH = Path.home() / ".agent-bom" / "baseline.json"


# ---------------------------------------------------------------------------
# Finding key type
# ---------------------------------------------------------------------------

# A delta key uniquely identifies a vulnerability in a package at a version.
# Using (vuln_id, package_name, package_version) gives stable, human-readable keys.
DeltaKey = tuple[str, str, str]


def _make_key(vuln_id: str, package: str) -> DeltaKey:
    """Build a delta key from a blast_radius JSON item.

    ``package`` is in ``name@version`` format as serialized by json_fmt.py.
    """
    name, _, version = package.partition("@")
    return (vuln_id.upper(), name.lower(), version or "")


def extract_delta_keys(scan_json: dict) -> set[DeltaKey]:
    """Extract the set of finding keys from a serialized scan output dict."""
    keys: set[DeltaKey] = set()
    for item in scan_json.get("blast_radius", []):
        vuln_id = item.get("vulnerability_id", "")
        package = item.get("package", "")
        if vuln_id and package:
            keys.add(_make_key(vuln_id, package))
    return keys


# ---------------------------------------------------------------------------
# Baseline I/O
# ---------------------------------------------------------------------------


def load_baseline(path: str | Path) -> dict:
    """Load a baseline scan JSON from disk.

    Returns the parsed dict, or raises ``FileNotFoundError`` / ``ValueError``
    if the file is missing or not valid scan output.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Baseline file not found: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Baseline file is not valid JSON: {p}") from exc
    if "blast_radius" not in data:
        raise ValueError(f"Baseline file does not look like an agent-bom scan output (missing 'blast_radius' key): {p}")
    return data


def save_baseline(scan_json: dict, path: str | Path | None = None) -> Path:
    """Persist a scan result as the new baseline.

    Writes to ``path`` (or ``~/.agent-bom/baseline.json`` by default).
    Returns the path written.
    """
    p = Path(path) if path else _DEFAULT_BASELINE_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(scan_json, indent=2), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Core diff logic
# ---------------------------------------------------------------------------


class DeltaResult:
    """Result of comparing current scan findings against a baseline."""

    def __init__(
        self,
        new_items: list[dict],
        pre_existing_items: list[dict],
        baseline_path: Optional[str],
    ) -> None:
        self.new_items = new_items  # findings not in baseline
        self.pre_existing_items = pre_existing_items  # findings that were already in baseline
        self.baseline_path = baseline_path

    @property
    def new_count(self) -> int:
        return len(self.new_items)

    @property
    def pre_existing_count(self) -> int:
        return len(self.pre_existing_items)

    @property
    def has_new(self) -> bool:
        return bool(self.new_items)

    def summary_line(self) -> str:
        parts = []
        if self.new_count:
            parts.append(f"{self.new_count} new")
        if self.pre_existing_count:
            parts.append(f"{self.pre_existing_count} pre-existing (suppressed)")
        if not parts:
            return "No findings (delta clean)"
        return ", ".join(parts)


def compute_delta(
    current_scan: dict,
    baseline: dict,
) -> DeltaResult:
    """Diff current scan against baseline; return new and pre-existing items.

    Args:
        current_scan: serialized scan JSON (output of ``to_json(report)``).
        baseline: previously saved scan JSON to compare against.

    Returns:
        :class:`DeltaResult` with ``new_items`` (not in baseline) and
        ``pre_existing_items`` (already in baseline).
    """
    baseline_keys = extract_delta_keys(baseline)
    _logger.debug("Baseline has %d findings", len(baseline_keys))

    new_items: list[dict] = []
    pre_existing_items: list[dict] = []

    for item in current_scan.get("blast_radius", []):
        vuln_id = item.get("vulnerability_id", "")
        package = item.get("package", "")
        if not vuln_id or not package:
            _logger.debug("Skipping malformed blast_radius item: %s", item)
            continue
        key = _make_key(vuln_id, package)
        if key in baseline_keys:
            pre_existing_items.append(item)
        else:
            new_items.append(item)

    _logger.info(
        "Delta: %d new, %d pre-existing (baseline had %d)",
        len(new_items),
        len(pre_existing_items),
        len(baseline_keys),
    )
    return DeltaResult(
        new_items=new_items,
        pre_existing_items=pre_existing_items,
        baseline_path=None,
    )


def apply_delta_to_scan(
    scan_json: dict,
    delta: DeltaResult,
) -> dict:
    """Return a modified scan dict containing only new findings.

    The ``summary`` counters are also recomputed to reflect delta-only counts.
    The original scan dict is NOT mutated; a shallow copy with replaced
    ``blast_radius`` and updated ``summary`` is returned.
    """
    result = dict(scan_json)
    result["blast_radius"] = delta.new_items
    result["delta"] = {
        "enabled": True,
        "new_count": delta.new_count,
        "pre_existing_count": delta.pre_existing_count,
        "baseline_path": delta.baseline_path,
    }
    # Recompute summary counts
    if "summary" in result and isinstance(result["summary"], dict):
        summary = dict(result["summary"])
        summary["total_vulnerabilities"] = delta.new_count
        summary["delta_note"] = delta.summary_line()
        result["summary"] = summary
    return result
