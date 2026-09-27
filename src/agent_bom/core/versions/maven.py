"""Canonical maven rules for ecosystem version comparison."""

from __future__ import annotations

_MAVEN_QUALIFIERS = ("alpha", "beta", "milestone", "rc", "snapshot", "", "sp")


_MAVEN_RELEASE_INDEX = str(_MAVEN_QUALIFIERS.index(""))


_MAVEN_ALIASES = {"ga": "", "final": "", "release": "", "cr": "rc"}


_MAVEN_SHORT_QUALIFIERS = {"a": "alpha", "b": "beta", "m": "milestone"}


def _maven_qualifier_key(qualifier: str) -> str:
    """Sort key for a Maven qualifier token.

    Known qualifiers map to their single-digit index; unknown qualifiers map to
    ``"7-<qualifier>"`` so they sort lexically above every known one.
    """
    try:
        return str(_MAVEN_QUALIFIERS.index(qualifier))
    except ValueError:
        return f"{len(_MAVEN_QUALIFIERS)}-{qualifier}"


class _MavenInt:
    """A numeric Maven token."""

    __slots__ = ("value",)

    def __init__(self, raw: str) -> None:
        self.value = int(raw or "0")

    def is_null(self) -> bool:
        return self.value == 0


class _MavenStr:
    """A qualifier (non-numeric) Maven token."""

    __slots__ = ("value",)

    def __init__(self, raw: str, followed_by_digit: bool) -> None:
        value = raw
        if followed_by_digit and len(value) == 1:
            value = _MAVEN_SHORT_QUALIFIERS.get(value, value)
        self.value = _MAVEN_ALIASES.get(value, value)

    def is_null(self) -> bool:
        return _maven_qualifier_key(self.value) == _MAVEN_RELEASE_INDEX


class _MavenList(list):
    """A nested Maven token sequence (one per ``-`` separated segment)."""

    def is_null(self) -> bool:
        return len(self) == 0

    def normalize(self) -> None:
        """Trim trailing "null" tokens (0, "", final, ga) from the end."""
        for index in range(len(self) - 1, -1, -1):
            item = self[index]
            if item.is_null():
                del self[index]
            elif not isinstance(item, _MavenList):
                break


def _maven_item_rank(item: object) -> int:
    """Cross-type ordering: qualifier < list < numeric."""
    if isinstance(item, _MavenStr):
        return 0
    if isinstance(item, _MavenList):
        return 1
    return 2


def _maven_compare_items(left: object, right: object) -> int:
    """Compare two Maven tokens, where ``None`` is the padded null token."""
    if left is None and right is None:
        return 0
    if left is None:
        return -_maven_compare_items(right, None)
    if right is None:
        if isinstance(left, _MavenInt):
            return 0 if left.value == 0 else 1
        if isinstance(left, _MavenStr):
            key = _maven_qualifier_key(left.value)
            return (key > _MAVEN_RELEASE_INDEX) - (key < _MAVEN_RELEASE_INDEX)
        # A list compares against null through its first token.
        if isinstance(left, _MavenList):
            return 0 if not left else _maven_compare_items(left[0], None)
        return 0

    left_rank = _maven_item_rank(left)
    right_rank = _maven_item_rank(right)
    if left_rank != right_rank:
        return (left_rank > right_rank) - (left_rank < right_rank)

    if isinstance(left, _MavenInt) and isinstance(right, _MavenInt):
        return (left.value > right.value) - (left.value < right.value)
    if isinstance(left, _MavenStr) and isinstance(right, _MavenStr):
        left_key = _maven_qualifier_key(left.value)
        right_key = _maven_qualifier_key(right.value)
        return (left_key > right_key) - (left_key < right_key)

    # Both lists: element-wise, padding the shorter side with null.
    assert isinstance(left, _MavenList) and isinstance(right, _MavenList)
    for index in range(max(len(left), len(right))):
        left_item = left[index] if index < len(left) else None
        right_item = right[index] if index < len(right) else None
        result = _maven_compare_items(left_item, right_item)
        if result:
            return result
    return 0


def _maven_parse(version: str) -> _MavenList:
    """Tokenize a Maven version into the nested item list the spec describes."""
    version = version.strip().lower()
    root = _MavenList()
    current = root
    stack = [root]
    is_digit = False
    start = 0

    def parse_item(digit: bool, buf: str) -> object:
        return _MavenInt(buf.lstrip("0") or "0") if digit else _MavenStr(buf, False)

    def descend() -> None:
        """Append a fresh sublist to the current list and make it current."""
        nonlocal current
        nested = _MavenList()
        current.append(nested)
        current = nested
        stack.append(nested)

    for index, char in enumerate(version):
        if char == ".":
            current.append(_MavenInt("0") if index == start else parse_item(is_digit, version[start:index]))
            start = index + 1
        elif char in "-_":
            current.append(_MavenInt("0") if index == start else parse_item(is_digit, version[start:index]))
            start = index + 1
            descend()
        elif char.isdigit():
            # A character→digit transition is equivalent to a hyphen. Upstream
            # nests the qualifier itself one level deeper whenever the current
            # list already holds something, so a trailing qualifier sorts as a
            # sublist (below any number) rather than as a sibling token.
            if not is_digit and index > start:
                if current:
                    descend()
                current.append(_MavenStr(version[start:index], True))
                start = index
                descend()
            is_digit = True
        else:
            # A digit→character transition is equivalent to a hyphen.
            if is_digit and index > start:
                current.append(parse_item(True, version[start:index]))
                start = index
                descend()
            is_digit = False

    if len(version) > start:
        # Same nesting rule for the final token: ``2.0.a`` is ``2, [a]`` — a
        # sublist that sorts BELOW ``2-1``'s ``[1]`` — not the sibling ``2, 0,
        # a`` that would sort above it. Treating it as a sibling made the whole
        # cross-type ordering wrong for any version ending in a qualifier.
        if not is_digit and current:
            descend()
        current.append(parse_item(is_digit, version[start:]))

    while stack:
        stack.pop().normalize()
    return root


def _compare_maven_versions(left: str, right: str) -> int:
    """Compare two Maven versions per the Maven version order specification."""
    return _maven_compare_items(_maven_parse(left), _maven_parse(right))
