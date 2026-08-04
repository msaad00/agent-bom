"""Install a fake provider SDK in ``sys.modules`` without leaking the real one.

``patch.dict(sys.modules, fakes)`` shadows only the names it lists, which is not
enough for a namespace package like ``google.cloud``. A stub parent is a bare
``types.ModuleType`` with no ``__path__``, so ``_handle_fromlist`` skips it
entirely and ``from google.cloud import asset_v1`` is resolved solely by
CPython's ``IMPORT_FROM`` fallback to ``sys.modules["google.cloud.asset_v1"]``.
Whatever an earlier test in the same process left resident there is handed back —
so a test that stubs only part of a namespace silently binds real SDK modules,
and its outcome depends on which tests ran before it.

Mapping the extra names to ``None`` does not close the hole either: the same
fallback returns the ``None`` object rather than raising, and the caller then
fails on ``None.SomeClient``. The entries have to be removed outright, which is
what :func:`patch_sdk_namespace` does — and restores on exit.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any


@contextmanager
def patch_sdk_namespace(fakes: dict[str, Any], *roots: str) -> Iterator[None]:
    """Install *fakes* as the ONLY modules importable under *roots*.

    Every other resident module under a root is removed for the duration, so the
    code under test sees exactly the SDK surface the fakes describe — the same on
    every run, whatever ran before. The real entries are restored on exit.
    """
    prefixes = tuple(f"{root}." for root in roots)

    def in_scope(name: str) -> bool:
        return name in roots or name.startswith(prefixes)

    outside = sorted(name for name in fakes if not in_scope(name))
    if outside:
        raise ValueError(f"fake modules outside the declared roots {roots}: {outside}")

    saved = {name: module for name, module in sys.modules.items() if in_scope(name)}
    for name in saved:
        del sys.modules[name]
    sys.modules.update(fakes)
    try:
        yield
    finally:
        for name in [name for name in sys.modules if in_scope(name)]:
            del sys.modules[name]
        sys.modules.update(saved)
