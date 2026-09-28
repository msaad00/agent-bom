"""Traversal behind :func:`agent_bom.security.sanitize_sensitive_payload`.

A finished report has millions of leaves but few distinct (field, value)
pairs, so per-leaf recursion dominated export time. Scalar and already-cached
string children are resolved inline; every string still passes through the
same field-sensitive rules in ``security`` and the same per-traversal cache.
"""

from __future__ import annotations

from agent_bom import security
from agent_bom.redaction.provenance import PROVENANCE_KEYS, sanitize_provenance_marker

_CACHE_LIMIT = 262_144
_CACHE_MISS = object()
_DEPTH_LIMIT = 24
# Exact types copied through without a call. Subclasses (IntEnum, StrEnum, ...)
# still take the general path, as before.
_PASSTHROUGH_TYPES = frozenset({type(None), bool, int, float})

StringCache = dict[tuple[str | None, str, int], object]
KeyCache = dict[str, str]


def _redact_string(value: str, key: object | None, key_text: str | None, max_str_len: int, string_cache: StringCache) -> object:
    cache_key = (key_text, value, max_str_len)
    cached = string_cache.get(cache_key, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        return cached
    marker = sanitize_provenance_marker(value) if key_text in PROVENANCE_KEYS else None
    sanitized_value = marker if marker is not None else security._sanitize_sensitive_string(value, key=key, max_str_len=max_str_len)
    if len(string_cache) < _CACHE_LIMIT:
        string_cache[cache_key] = sanitized_value
    return sanitized_value


def _clean_key(raw_key: object, key_cache: KeyCache) -> str:
    raw_key_text = str(raw_key)
    clean_key = key_cache.get(raw_key_text)
    if clean_key is None:
        clean_key = security.sanitize_text(raw_key, max_len=200)
        if len(key_cache) < _CACHE_LIMIT:
            key_cache[raw_key_text] = clean_key
    return clean_key


def _redact_dict(value: dict, max_str_len: int, depth: int, string_cache: StringCache, key_cache: KeyCache) -> dict[str, object]:
    inline = depth < _DEPTH_LIMIT
    sanitized: dict[str, object] = {}
    for raw_key, raw_value in value.items():
        clean_key = _clean_key(raw_key, key_cache)
        value_type = type(raw_value)
        if inline and value_type in _PASSTHROUGH_TYPES:
            sanitized[clean_key] = raw_value
        elif inline and value_type is str:
            cached = string_cache.get((clean_key, raw_value, max_str_len), _CACHE_MISS)
            if cached is _CACHE_MISS:
                cached = _redact_string(raw_value, clean_key, clean_key, max_str_len, string_cache)
            sanitized[clean_key] = cached
        else:
            sanitized[clean_key] = redact_payload(raw_value, clean_key, max_str_len, depth, string_cache, key_cache)
    return sanitized


def _redact_items(
    value: list | tuple | set, key: object | None, max_str_len: int, depth: int, string_cache: StringCache, key_cache: KeyCache
) -> list[object]:
    inline = depth < _DEPTH_LIMIT
    key_text = str(key) if key is not None else None
    items: list[object] = []
    for item in list(value):
        item_type = type(item)
        if inline and item_type in _PASSTHROUGH_TYPES:
            items.append(item)
        elif inline and item_type is str:
            cached = string_cache.get((key_text, item, max_str_len), _CACHE_MISS)
            if cached is _CACHE_MISS:
                cached = _redact_string(item, key, key_text, max_str_len, string_cache)
            items.append(cached)
        else:
            items.append(redact_payload(item, key, max_str_len, depth, string_cache, key_cache))
    return items


def redact_payload(
    value: object, key: object | None, max_str_len: int, depth: int, string_cache: StringCache, key_cache: KeyCache
) -> object:
    """Redact ``value`` found under ``key`` at ``depth`` (same rules as the original recursive walk)."""
    if depth >= _DEPTH_LIMIT:
        return "[truncated]"
    if value is None or isinstance(value, bool | int | float):
        return value
    if isinstance(value, str):
        return _redact_string(value, key, str(key) if key is not None else None, max_str_len, string_cache)
    if isinstance(value, dict):
        return _redact_dict(value, max_str_len, depth + 1, string_cache, key_cache)
    if isinstance(value, list | tuple | set):
        return _redact_items(value, key, max_str_len, depth + 1, string_cache, key_cache)
    return security.sanitize_text(value, max_len=max_str_len)
