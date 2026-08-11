"""One definition of what ``composite_risk`` means.

``AttackPath.composite_risk`` had two producers on two different scales:
``routes/graph._node_risk_100`` normalised to 0–100, while
``demo_estate/estate_graph._chain_risk`` returned a raw CVSS 0–10. Both wrote
the same field, and ``_derived_attack_paths`` sorted the merged list by it — so
the exposure-path ranking interleaved two unit systems.

The effect was not subtle. On the demo estate every hand-built showcase path
outranked every correlated-estate path *by construction rather than by risk*:

    risk buckets: {'0-10': 2116, '10-50': 1, '50-100': 27}
    best estate-correlated path : 8.0
    worst showcase-derived path : 48.0
    rank of the first estate-correlated path: 74

The correlated estate is the product's central claim, and it could not reach the
top of its own queue.

``graph/webhooks.py`` inherited the same ambiguity and banded the field on 0–10
thresholds, so a shipped alert read "Composite risk 100.0/10" and treated 9 out
of 100 as critical.

So the normalisation lives here, once, and every producer calls it. A second
copy is how the two scales diverged in the first place.
"""

from __future__ import annotations

# The canonical range for `composite_risk` and every node/path risk derived
# from it. 0–100 rather than 0–10 because the graph blends CVSS with
# severity-rank and exposure signals that have no CVSS equivalent.
RISK_SCALE_MAX = 100.0

# Values at or below this are read as CVSS-style (0–10) and lifted. A genuine
# 0–100 score of 8 and a CVSS of 8.0 are indistinguishable in a bare float, so
# the boundary is a deliberate, documented convention rather than a guess: the
# producers that emit CVSS never exceed 10, and the ones that emit 0–100 are
# dominated by values well above it.
_CVSS_SCALE_MAX = 10.0


def cvss_to_risk_100(value: float | int | None) -> float:
    """Convert a KNOWN CVSS (0–10) score onto the canonical scale.

    Prefer this wherever the caller knows its input is CVSS. It is a plain,
    monotonic 10x with a clamp — no guessing — so it has none of the boundary
    ambiguity that :func:`normalize_risk_to_100` cannot avoid.
    """
    try:
        risk = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    return max(0.0, min(RISK_SCALE_MAX, risk * 10.0))


def normalize_risk_to_100(value: float | int | None) -> float:
    """Return ``value`` on the canonical 0–100 scale, inferring its input scale.

    For callers reading ``risk_score`` off arbitrary nodes, where producers have
    historically written both CVSS and 0–100 values into one field.

    **This is deliberately not monotonic, and cannot be.** A bare float carries
    no unit, so 9.9 is read as CVSS and lifted to 99.0 while 11.0 is read as
    already-scaled and left at 11.0 — a value that is numerically larger maps
    lower. That discontinuity at the boundary is inherent to inferring a unit
    that was never recorded; it is documented here rather than hidden, and it is
    why :func:`cvss_to_risk_100` exists for callers that do know.
    """
    try:
        risk = float(value or 0.0)
    except (TypeError, ValueError):
        return 0.0
    if risk <= 0.0:
        return 0.0
    if risk <= _CVSS_SCALE_MAX:
        risk *= 10.0
    return max(0.0, min(RISK_SCALE_MAX, risk))


__all__ = ["RISK_SCALE_MAX", "cvss_to_risk_100", "normalize_risk_to_100"]
