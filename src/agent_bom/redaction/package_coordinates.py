"""Recognize explicit package coordinates embedded in diagnostic text."""

from __future__ import annotations

import re
from functools import lru_cache

_COORDINATE = re.compile(r"\bpkg:[a-z][a-z0-9.+-]*(?:/|:)[^\s<>\"'|?#]+")
_MAVEN = re.compile(r"\b(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*:[A-Za-z0-9_.-]+@[^\s<>\"'|?#]+")
_VERSION = re.compile(r"v?\d[0-9A-Za-z._+:-]{0,255}")


@lru_cache(maxsize=512)
def _valid_coordinate(token: str) -> bool:
    # Internal graph IDs use pkg:ecosystem:name@version; PURLs use slashes.
    head, separator, tail = token[4:].partition(":")
    if separator and "/" not in head:
        token = "pkg:" + head + "/" + tail.replace(":", "/", 1)
    try:
        from packageurl import PackageURL

        parsed = PackageURL.from_string(token)
    except (ImportError, ValueError):
        return False
    return bool(parsed.name and parsed.version and _VERSION.fullmatch(parsed.version))


def package_coordinate_spans(text: str) -> list[tuple[int, int]]:
    """Return validated coordinate spans, excluding qualifiers and fragments.

    Only these spans can exempt an email-shaped package/version join. This
    does not exempt credentials, URLs, nearby addresses or bare email strings.
    """
    spans = []
    for match in _COORDINATE.finditer(text):
        token = match.group().rstrip(",;)]}")
        if _valid_coordinate(token):
            spans.append((match.start(), match.start() + len(token)))
    for match in _MAVEN.finditer(text):
        token = match.group().rstrip(",;)]}")
        if _valid_coordinate("pkg:maven:" + token):
            spans.append((match.start(), match.start() + len(token)))
    return spans
