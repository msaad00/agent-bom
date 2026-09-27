"""Canonical ranges rules for ecosystem version comparison."""

from __future__ import annotations

from functools import lru_cache

from agent_bom.core.versions.go import _go_pseudo_timestamp
from agent_bom.core.versions.ordering import compare_version_order
from agent_bom.core.versions.validation import _looks_like_commit_sha


def normalize_introduced(introduced: str | None) -> str | None:
    """Resolve an OSV ``introduced`` bound, returning ``None`` when unbounded.

    The OSV schema defines ``"0"`` as a sentinel — "a version that sorts before
    any other version" — not as a version string to compare against. Comparing
    a real version to the literal ``"0"`` gives the wrong answer whenever the
    version sorts BELOW zero in its own ecosystem's order, and Go pseudo-
    versions do exactly that: ``v0.0.0-20200622213623-75b288015ac9`` is a
    pre-release of ``0.0.0``. Every advisory window opening at the sentinel then
    excluded every pseudo-version-pinned module — a silent, total recall loss
    for the most common way an untagged Go dependency is pinned.

    Only ``introduced`` carries this sentinel. ``fixed`` and ``last_affected``
    keep their literal meaning: nothing is "fixed before every version".
    """
    if introduced is None:
        return None
    bound = introduced.strip()
    if not bound or bound == "0":
        return None
    return bound


def _go_window_excludes(version: str, intro: str | None, fix: str | None, last: str | None, ecosystem: str) -> bool:
    """Apply timestamp precedence before the general Go bound checks."""
    ver_ts = _go_pseudo_timestamp(version)
    if ver_ts:
        for boundary, is_lower in ((intro, True), (fix, False), (last, False)):
            if not boundary:
                continue
            boundary_ts = _go_pseudo_timestamp(boundary)
            cmp: int | None
            if boundary_ts:
                cmp = (ver_ts > boundary_ts) - (ver_ts < boundary_ts)
            else:
                # Tagged bound: route the pseudo-vs-tagged comparison
                # through compare_version_order instead of skipping it,
                # so the boundary still constrains range membership.
                cmp = compare_version_order(version, boundary, ecosystem)
            if cmp is None:
                continue
            if is_lower and cmp < 0:
                return True
            if not is_lower and boundary == fix and cmp >= 0:
                return True
            if not is_lower and boundary == last and cmp > 0:
                return True

    return False


@lru_cache(maxsize=65536)
def _resolve_version_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str,
) -> tuple[bool, tuple[str, ...]]:
    """Return ``(affected, dropped_bounds)`` for the supplied advisory bounds."""
    dropped: list[str] = []
    intro = normalize_introduced(introduced)
    fix = fixed or None
    last = last_affected or None

    # Git-commit bounds (common in OSS-Fuzz / OSV-2022-* advisories) cannot
    # establish semver range membership — compare_version_order returns None
    # and falling through would mark every version as affected.
    if any(boundary and _looks_like_commit_sha(boundary) for boundary in (intro, fix, last)):
        return False, ()

    if ecosystem.lower() == "go" and _go_window_excludes(version, intro, fix, last, ecosystem):
        return False, ()

    # Fail CLOSED per bound: a comparison that cannot be performed is never
    # grounds for a match. An unparseable UPPER bound (fixed / last_affected)
    # means the version cannot be placed inside the range — no match. An
    # unparseable LOWER bound (introduced) is treated as satisfied so that a
    # parseable upper bound can still confirm a real match — unless it was the
    # only bound, in which case no comparison was performed at all.
    intro_unperformed = False
    if intro:
        intro_cmp = compare_version_order(version, intro, ecosystem)
        if intro_cmp is not None and intro_cmp < 0:
            return False, tuple(dropped)
        if intro_cmp is None:
            dropped.append(intro)
            intro_unperformed = True
    if fix:
        fix_cmp = compare_version_order(version, fix, ecosystem)
        if fix_cmp is None:
            dropped.append(fix)
            return False, tuple(dropped)
        if fix_cmp >= 0:
            return False, tuple(dropped)
    if last:
        last_cmp = compare_version_order(version, last, ecosystem)
        if last_cmp is None:
            dropped.append(last)
            return False, tuple(dropped)
        if last_cmp > 0:
            return False, tuple(dropped)
    if intro_unperformed and not fix and not last:
        return False, tuple(dropped)
    return True, tuple(dropped)
