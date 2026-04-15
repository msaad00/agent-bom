"""Shared helpers for CLI option decorator groups."""

from __future__ import annotations


def _apply(decorators):
    """Apply a list of click decorators bottom-up (last in list = outermost)."""

    def wrapper(fn):
        for dec in reversed(decorators):
            fn = dec(fn)
        return fn

    return wrapper
