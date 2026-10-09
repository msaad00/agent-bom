"""Necessary-condition prefilters that let a scanner skip regexes that cannot match.

Content scanners run many independent patterns over every file, and almost all
of them match nothing. Each compiled pattern is parsed once to find something
every match must contain: one of a set of literal substrings, or at least one
non-ASCII character. When the content lacks it, ``finditer`` would yield
nothing, so skipping the regex is exact. Anything this module cannot prove
leaves the pattern unfiltered; it never changes which matches are produced.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from functools import cache, cached_property
from re import _constants as sre_constants  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

_MIN_LITERAL = 2
_ZERO_WIDTH = {sre_constants.AT, sre_constants.ASSERT, sre_constants.ASSERT_NOT}


@dataclass(frozen=True)
class Requirement:
    """What every match of a pattern must contain."""

    literals: tuple[str, ...] = ()
    non_ascii: bool = False
    ignorecase: bool = False


class ContentView:
    """One file's text plus the derived forms prefilter checks share."""

    def __init__(self, content: str) -> None:
        self.content = content

    @cached_property
    def is_ascii(self) -> bool:
        return self.content.isascii()

    @cached_property
    def lowered(self) -> str:
        return self.content.lower()


def _non_ascii_item(op: Any, av: Any) -> bool:
    if op is sre_constants.LITERAL:
        return bool(av >= 0x80)
    if op is sre_constants.IN:
        members = list(av)
        if not members or any(member_op is sre_constants.NEGATE for member_op, _ in members):
            return False
        return all(
            (member_op is sre_constants.LITERAL and member_av >= 0x80) or (member_op is sre_constants.RANGE and member_av[0] >= 0x80)
            for member_op, member_av in members
        )
    return False


def _best(candidates: list[Requirement]) -> Requirement | None:
    if any(candidate.non_ascii for candidate in candidates):
        return Requirement(non_ascii=True)
    literal_sets = [candidate for candidate in candidates if candidate.literals]
    if not literal_sets:
        return None
    return max(literal_sets, key=lambda candidate: min(len(literal) for literal in candidate.literals))


def _branch_requirement(alternatives: list[Any]) -> Requirement | None:
    requirements = [_sequence_requirement(list(alternative)) for alternative in alternatives]
    if any(requirement is None for requirement in requirements):
        return None
    if all(requirement is not None and requirement.non_ascii for requirement in requirements):
        return Requirement(non_ascii=True)
    if any(requirement is not None and requirement.non_ascii for requirement in requirements):
        return None
    literals = tuple(literal for requirement in requirements if requirement is not None for literal in requirement.literals)
    return Requirement(literals=literals)


def _item_requirement(op: Any, av: Any) -> Requirement | None:
    if _non_ascii_item(op, av):
        return Requirement(non_ascii=True)
    if op is sre_constants.SUBPATTERN:
        _group, add_flags, del_flags, sub = av
        if add_flags or del_flags:
            return None
        return _sequence_requirement(list(sub))
    if op is sre_constants.BRANCH:
        return _branch_requirement(av[1])
    if op in (sre_constants.MAX_REPEAT, sre_constants.MIN_REPEAT, sre_constants.POSSESSIVE_REPEAT):
        minimum, _maximum, sub = av
        return _sequence_requirement(list(sub)) if minimum >= 1 else None
    return None


def _sequence_requirement(items: list[tuple[Any, Any]]) -> Requirement | None:
    """Best requirement of a sequence: every non-optional element is mandatory."""
    candidates: list[Requirement] = []
    run: list[str] = []

    def flush() -> None:
        if len(run) >= _MIN_LITERAL:
            candidates.append(Requirement(literals=("".join(run),)))
        run.clear()

    for op, av in items:
        if op is sre_constants.LITERAL and av < 0x80:
            run.append(chr(av))
            continue
        if op in _ZERO_WIDTH:
            # Zero-width items constrain position, not content: a literal run
            # interrupted by one is still contiguous text in every match.
            continue
        flush()
        requirement = _item_requirement(op, av)
        if requirement is not None:
            candidates.append(requirement)
    flush()
    return _best(candidates)


@cache
def _requirement_for(pattern: str, flags: int) -> Requirement | None:
    try:
        parsed = sre_parse.parse(pattern, flags)
    except (re.error, TypeError, ValueError):
        return None
    requirement = _sequence_requirement(list(parsed))
    if requirement is None or not parsed.state.flags & re.IGNORECASE:
        return requirement
    if requirement.non_ascii:
        # Case-insensitive non-ASCII items can match ASCII text (U+212A KELVIN
        # SIGN matches "k"), so ASCII content proves nothing.
        return None
    return Requirement(literals=tuple(literal.lower() for literal in requirement.literals), ignorecase=True)


def requirement_for(regex: re.Pattern[str]) -> Requirement | None:
    """Return what every match of *regex* must contain, or None when unknown."""
    if not isinstance(regex.pattern, str):
        return None
    return _requirement_for(regex.pattern, regex.flags)


def may_match(regex: re.Pattern[str], view: ContentView) -> bool:
    """False only when *regex* provably has no match in *view*."""
    requirement = requirement_for(regex)
    if requirement is None:
        return True
    if requirement.non_ascii:
        return not view.is_ascii
    if not requirement.ignorecase:
        return any(literal in view.content for literal in requirement.literals)
    # Case-insensitive matching of an ASCII literal can also hit a few
    # non-ASCII code points (for example U+212A KELVIN SIGN for "k"); only
    # ASCII text is safe to compare in lowercase.
    if not view.is_ascii:
        return True
    return any(literal in view.lowered for literal in requirement.literals)


def finditer(regex: re.Pattern[str], view: ContentView) -> Iterator[re.Match[str]]:
    """``regex.finditer(view.content)``, skipped when it provably yields nothing."""
    if not may_match(regex, view):
        return iter(())
    return regex.finditer(view.content)


__all__ = ["ContentView", "Requirement", "finditer", "may_match", "requirement_for"]
