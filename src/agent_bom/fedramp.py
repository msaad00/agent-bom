"""FedRAMP compliance framework — NIST 800-53 baselines for federal cloud.

FedRAMP (Federal Risk and Authorization Management Program) defines three
impact baselines (Low, Moderate, High) that select subsets of NIST SP 800-53
Rev 5 controls.  This module wraps :mod:`agent_bom.nist_800_53` and filters
tags to the selected baseline, prefixing each with ``FedRAMP-`` for clarity.

Reference: https://www.fedramp.gov/baselines/
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from agent_bom import nist_800_53 as _nist

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

# ─── FedRAMP Baselines ───────────────────────────────────────────────────────
# Subsets of NIST 800-53 controls required at each impact level.
# Each higher level includes all controls from the lower level(s).

FEDRAMP_LOW: frozenset[str] = frozenset(
    {
        "RA-5",
        "SI-2",
        "SI-3",
        "SI-4",
        "CM-6",
        "CM-7",
        "CM-8",
        "AC-3",
        "AC-6",
        "AU-2",
        "AU-6",
        "IA-5",
        "SC-8",
        "SC-13",
    }
)

FEDRAMP_MODERATE: frozenset[str] = FEDRAMP_LOW | frozenset(
    {
        "RA-7",
        "SI-5",
        "SI-7",
        "SI-10",
        "SR-3",
        "IR-5",
        "IR-6",
        "SC-12",
        "SC-17",
        "SC-28",
        "IA-7",
    }
)

FEDRAMP_HIGH: frozenset[str] = FEDRAMP_MODERATE | frozenset(
    {
        "SI-16",
        "SR-4",
        "SR-5",
        "SR-11",
    }
)

_BASELINES: dict[str, frozenset[str]] = {
    "low": FEDRAMP_LOW,
    "moderate": FEDRAMP_MODERATE,
    "high": FEDRAMP_HIGH,
}


# ─── Tagger ───────────────────────────────────────────────────────────────────


def tag_blast_radius(br: BlastRadius, baseline: str = "moderate") -> list[str]:
    """Return sorted FedRAMP-prefixed control IDs for the given baseline.

    Delegates to :func:`nist_800_53.tag_blast_radius` and filters the result
    to only controls present in the selected FedRAMP baseline (low, moderate,
    or high).  Each tag is prefixed with ``FedRAMP-`` for disambiguation.
    """
    allowed = _BASELINES.get(baseline.lower(), FEDRAMP_MODERATE)
    raw_tags = _nist.tag_blast_radius(br)
    return sorted(f"FedRAMP-{t}" for t in raw_tags if t in allowed)
