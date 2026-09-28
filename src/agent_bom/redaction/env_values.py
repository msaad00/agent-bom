"""Secret detection for non-scalar environment values.

A container's ``str()`` mixes brackets, quotes and every element into one
string, which the entropy heuristic misreads. Each leaf is judged on its own
instead, with the same value checks a scalar env value receives. The checks
are passed in so this module stays import-free for ``agent_bom.security``.
"""

from __future__ import annotations

from collections.abc import Callable

_DEPTH_LIMIT = 8


def container_has_secret(
    value: object,
    leaf_is_secret: Callable[[str], bool],
    key_is_credential: Callable[[str], bool],
    depth: int = 0,
) -> bool:
    """Whether any leaf, or any dict key naming a credential, is sensitive."""
    if depth > _DEPTH_LIMIT:
        return True
    if isinstance(value, dict):
        return any(
            key_is_credential(str(key)) or container_has_secret(child, leaf_is_secret, key_is_credential, depth + 1)
            for key, child in value.items()
        )
    if isinstance(value, list | tuple | set):
        return any(container_has_secret(child, leaf_is_secret, key_is_credential, depth + 1) for child in value)
    return leaf_is_secret(str(value))
