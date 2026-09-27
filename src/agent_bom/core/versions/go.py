"""Canonical go rules for ecosystem version comparison."""

from __future__ import annotations

from agent_bom.core.versions.validation import _GO_PSEUDO_RE


def _go_pseudo_timestamp(version: str) -> str | None:
    match = _GO_PSEUDO_RE.match(version)
    return match.group(1) if match else None


def _go_packaging_operand(version: str) -> str:
    """Return the ``X.Y.Z`` base of a Go version for packaging comparison.

    A pseudo-version (``vX.Y.Z-<ts>-<sha>``) is collapsed to its ``X.Y.Z``
    base so it can be ordered against an ordinary tagged bound; the
    date/sha suffix is not PEP 440-parsable on its own. Plain tags just
    lose the leading ``v``.
    """
    if _go_pseudo_timestamp(version):
        version = version.split("-", 1)[0]
    return version[1:] if version.startswith("v") else version


def _compare_go_versions(left: str, right: str) -> int | None:
    left_ts = _go_pseudo_timestamp(left)
    right_ts = _go_pseudo_timestamp(right)
    if left_ts and right_ts:
        return (left_ts > right_ts) - (left_ts < right_ts)
    try:
        from packaging.version import Version

        left_norm = _go_packaging_operand(left)
        right_norm = _go_packaging_operand(right)
        base_cmp = (Version(left_norm) > Version(right_norm)) - (Version(left_norm) < Version(right_norm))
        if base_cmp:
            return base_cmp
        # Same X.Y.Z base and exactly one side is a pseudo-version. A
        # pseudo-version is a pre-release of its base ("compares higher than its
        # base version, but lower than the next tagged version"), so it sorts
        # strictly BELOW the bare tag. Collapsing to equality here would let a
        # pseudo-version read as already past a fix bound.
        if bool(left_ts) != bool(right_ts):
            return -1 if left_ts else 1
        return 0
    except Exception:  # noqa: BLE001
        return None
