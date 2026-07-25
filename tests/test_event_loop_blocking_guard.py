"""Static guards for two defect classes that unit tests do not catch.

1. Credential verification on the event loop. ``KeyStore.verify`` runs scrypt
   and ``OIDCConfig.verify`` can fetch JWKS with a synchronous ``urlopen``.
   Both are reachable *before* a caller is authenticated, so running either
   inline lets an unauthenticated client stall every route on demand. Three
   separate instances of this shipped, each found only by reading code — this
   test finds the fourth.

2. Lifespan wiring. Inserting a helper between ``@asynccontextmanager`` and
   ``_lifespan`` silently moves the decorator onto the wrong function and
   breaks startup. Over 1,500 tests passed with exactly that bug in place
   because nothing asserted the lifespan is still a context manager.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_SRC = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "api"

# Modules that authenticate a caller. Add new auth surfaces here.
_AUTH_MODULES = (
    _SRC / "middleware.py",
    _SRC / "routes" / "enterprise.py",
    _SRC / "routes" / "proxy.py",
)

# Method names whose synchronous implementation blocks (scrypt / DB / network).
_BLOCKING_METHODS = {"verify"}


def _blocking_calls_in_async_defs(path: Path) -> list[str]:
    """Return ``file:line`` for blocking calls made directly inside ``async def``.

    Passing a bound method *by reference* to ``run_sync`` is the correct
    pattern and parses as an ``ast.Attribute``, not an ``ast.Call``, so it is
    naturally excluded.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"))
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.AsyncFunctionDef):
            continue
        for inner in ast.walk(node):
            if not isinstance(inner, ast.Call):
                continue
            func = inner.func
            if isinstance(func, ast.Attribute) and func.attr in _BLOCKING_METHODS:
                offenders.append(f"{path.name}:{inner.lineno} ({func.attr})")
    return offenders


@pytest.mark.parametrize("module", _AUTH_MODULES, ids=lambda p: p.name)
def test_credential_verification_never_runs_on_the_event_loop(module: Path) -> None:
    offenders = _blocking_calls_in_async_defs(module)
    assert not offenders, (
        "credential verification called directly inside an async function: "
        + ", ".join(offenders)
        + " — pass the bound method to anyio.to_thread.run_sync instead"
    )


def test_lifespan_is_still_an_async_context_manager() -> None:
    """Guards the decorator from drifting onto a neighbouring function."""
    from agent_bom.api.server import _lifespan

    manager = _lifespan(None)  # type: ignore[arg-type]
    is_context_manager = hasattr(manager, "__aenter__") and hasattr(manager, "__aexit__")
    # Close the underlying generator either way so the assertion below reports
    # the real problem instead of being masked by a cleanup error.
    gen = getattr(manager, "gen", manager)
    close = getattr(gen, "close", None)
    if callable(close):
        close()

    assert is_context_manager, (
        "_lifespan no longer returns an async context manager — check that @asynccontextmanager still sits directly above it"
    )


@pytest.mark.asyncio
async def test_worker_thread_limit_helper_is_a_plain_function() -> None:
    """It must stay callable, not become a context manager by decorator drift."""
    from agent_bom.api.server import _apply_worker_thread_limit

    assert _apply_worker_thread_limit() is None
