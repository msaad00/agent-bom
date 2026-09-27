"""npm dependency-spec classification and range resolution.

Implements the node-semver range grammar (``^``, ``~``, X-ranges, hyphen
ranges, comparator sets joined by ``||``, and the prerelease inclusion rule)
plus npm-pick-manifest's selection rule: a range resolves to the version the
``latest`` dist-tag names when that version satisfies it, else to the highest
satisfying version. A range is never floored to its lower bound, and a spec
that is not a registry version (git, URL, file, alias, workspace) never
resolves to a registry version.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal, Optional

NpmSpecKind = Literal["exact", "range", "tag", "non_registry"]

_EXACT_RE = re.compile(r"^(?:=\s*|v)?(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_PARTIAL_RE = re.compile(r"^v?(\d+|[xX*])(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$")
_COMPARATOR_RE = re.compile(r"^(\^|~>|~|>=|<=|>|<|=)?(.*)$")
_OPERATOR_SPACE_RE = re.compile(r"(\^|~>|~|>=|<=|>|<|=)\s+")
_HYPHEN_RE = re.compile(r"^\s*(\S+)\s+-\s+(\S+)\s*$")
_TAG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9._-]*$")
_NON_REGISTRY_PREFIXES = (
    "git+",
    "git:",
    "git@",
    "github:",
    "gitlab:",
    "bitbucket:",
    "gist:",
    "http:",
    "https:",
    "file:",
    "link:",
    "npm:",
    "workspace:",
    "portal:",
    "patch:",
    "catalog:",
)

_Key = tuple[int, int, int, tuple]
_Comparator = tuple[str, _Key]


def _prerelease_key(pre: Optional[str]) -> tuple:
    if not pre:
        return (1,)
    ids: list[tuple[int, int | str]] = []
    for part in pre.split("."):
        ids.append((0, int(part)) if part.isdigit() else (1, part))
    return (0, tuple(ids))


def _version_key(version: str) -> Optional[_Key]:
    match = _EXACT_RE.match(version.strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    return (int(major), int(minor), int(patch), _prerelease_key(pre))


def npm_exact_version(spec: str) -> Optional[str]:
    """Return the normalized version when *spec* pins exactly one version."""
    match = _EXACT_RE.match((spec or "").strip())
    if not match:
        return None
    major, minor, patch, pre = match.groups()
    core = f"{int(major)}.{int(minor)}.{int(patch)}"
    return f"{core}-{pre}" if pre else core


def _is_wild(part: Optional[str]) -> bool:
    return part is None or part in ("x", "X", "*")


def _key(major: int, minor: int, patch: int, pre: Optional[str] = None) -> _Key:
    return (major, minor, patch, _prerelease_key(pre))


def _lower_zero(major: int, minor: int, patch: int) -> _Key:
    # The ``-0`` prerelease floor node-semver uses for exclusive upper bounds.
    return (major, minor, patch, (0, ((0, 0),)))


def _desugar(op: str, text: str) -> Optional[list[_Comparator]]:
    match = _PARTIAL_RE.match(text)
    if not match:
        return None
    raw_major, raw_minor, raw_patch, pre = match.groups()
    if _is_wild(raw_major):
        # ``<*`` / ``>*`` admit nothing; every other operator on ``*`` admits anything.
        return [("<", _lower_zero(0, 0, 0))] if op in ("<", ">") else []
    major = int(raw_major)
    minor = None if _is_wild(raw_minor) else int(raw_minor)
    patch = None if _is_wild(raw_patch) else int(raw_patch)

    if op in ("", "="):
        if minor is None:
            return [(">=", _key(major, 0, 0)), ("<", _lower_zero(major + 1, 0, 0))]
        if patch is None:
            return [(">=", _key(major, minor, 0)), ("<", _lower_zero(major, minor + 1, 0))]
        return [("=", _key(major, minor, patch, pre))]
    if op in ("~", "~>"):
        lo = _key(major, minor or 0, patch or 0, pre)
        hi = _lower_zero(major + 1, 0, 0) if minor is None else _lower_zero(major, minor + 1, 0)
        return [(">=", lo), ("<", hi)]
    if op == "^":
        lo = _key(major, minor or 0, patch or 0, pre)
        if major > 0 or minor is None:
            hi = _lower_zero(major + 1, 0, 0)
        elif minor > 0 or patch is None:
            hi = _lower_zero(0, minor + 1, 0)
        else:
            hi = _lower_zero(0, 0, patch + 1)
        return [(">=", lo), ("<", hi)]
    if op == ">":
        if minor is None:
            return [(">=", _key(major + 1, 0, 0))]
        if patch is None:
            return [(">=", _key(major, minor + 1, 0))]
        return [(">", _key(major, minor, patch, pre))]
    if op == ">=":
        return [(">=", _key(major, minor or 0, patch or 0, pre))]
    if op == "<":
        if minor is None:
            return [("<", _lower_zero(major, 0, 0))]
        if patch is None:
            return [("<", _lower_zero(major, minor, 0))]
        return [("<", _key(major, minor, patch, pre))]
    if op == "<=":
        if minor is None:
            return [("<", _lower_zero(major + 1, 0, 0))]
        if patch is None:
            return [("<", _lower_zero(major, minor + 1, 0))]
        return [("<=", _key(major, minor, patch, pre))]
    return None


def _parse_set(text: str) -> Optional[list[_Comparator]]:
    text = text.strip()
    hyphen = _HYPHEN_RE.match(text)
    if hyphen:
        low = _desugar(">=", hyphen.group(1))
        high = _desugar("<=", hyphen.group(2))
        if low is None or high is None:
            return None
        return low + high
    text = _OPERATOR_SPACE_RE.sub(r"\1", text)
    comparators: list[_Comparator] = []
    for token in text.split():
        match = _COMPARATOR_RE.match(token)
        if not match:
            return None
        parsed = _desugar(match.group(1) or "", match.group(2))
        if parsed is None:
            return None
        comparators.extend(parsed)
    return comparators


def parse_npm_range(spec: str) -> Optional[list[list[_Comparator]]]:
    """Parse *spec* into OR-ed comparator sets, or ``None`` when it is not a range."""
    sets: list[list[_Comparator]] = []
    for part in (spec or "").split("||"):
        parsed = _parse_set(part)
        if parsed is None:
            return None
        sets.append(parsed)
    return sets


def _compare(op: str, key: _Key, bound: _Key) -> bool:
    if op == "=":
        return key == bound
    if op == ">":
        return key > bound
    if op == ">=":
        return key >= bound
    if op == "<":
        return key < bound
    return key <= bound


def _set_allows(comparators: list[_Comparator], key: _Key) -> bool:
    if not all(_compare(op, key, bound) for op, bound in comparators):
        return False
    if key[3] == (1,):
        return True
    # node-semver: a prerelease satisfies a set only when a comparator in that
    # set carries a prerelease on the same [major, minor, patch] tuple. The
    # synthetic ``-0`` exclusive upper bound does not count.
    return any(bound[:3] == key[:3] and bound[3] != (1,) and bound[3] != (0, ((0, 0),)) for _, bound in comparators)


def satisfies(version: str, spec: str) -> bool:
    key = _version_key(version)
    sets = parse_npm_range(spec)
    if key is None or sets is None:
        return False
    return any(_set_allows(comparators, key) for comparators in sets)


def max_satisfying(versions: Iterable[str], spec: str) -> Optional[str]:
    """Return the highest version in *versions* that satisfies *spec*."""
    sets = parse_npm_range(spec)
    if sets is None:
        return None
    best: Optional[tuple[_Key, str]] = None
    for version in versions:
        key = _version_key(version)
        if key is None or not any(_set_allows(comparators, key) for comparators in sets):
            continue
        if best is None or key > best[0]:
            best = (key, version)
    return best[1] if best else None


def classify_npm_spec(spec: str) -> NpmSpecKind:
    """Classify a package.json / install dependency spec."""
    text = (spec or "").strip()
    lowered = text.lower()
    if lowered.startswith(_NON_REGISTRY_PREFIXES) or "://" in lowered:
        return "non_registry"
    if npm_exact_version(text) is not None:
        return "exact"
    if parse_npm_range(text) is not None:
        return "range"
    if "/" in text or text.startswith((".", "~/")):
        return "non_registry"
    if _TAG_RE.match(text):
        return "tag"
    return "non_registry"


def resolve_npm_spec(spec: str, packument: dict) -> Optional[str]:
    """Resolve *spec* against registry *packument* metadata, npm-pick-manifest style.

    Returns ``None`` when nothing the registry publishes satisfies the spec, or
    when the spec does not name a registry version at all.
    """
    dist_tags = packument.get("dist-tags") or {}
    versions = list((packument.get("versions") or {}).keys())
    kind = classify_npm_spec(spec)
    if kind == "exact":
        exact = npm_exact_version(spec)
        return exact if exact in versions else None
    if kind == "tag":
        tagged = dist_tags.get(spec.strip())
        return tagged if isinstance(tagged, str) and tagged else None
    if kind != "range":
        return None
    latest = dist_tags.get("latest")
    if isinstance(latest, str) and latest and (not versions or latest in versions) and satisfies(latest, spec):
        return latest
    return max_satisfying(versions, spec)
