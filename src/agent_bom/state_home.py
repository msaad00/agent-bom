"""Single resolver for agent-bom's local data directory.

Every local store (graph, control plane, assets, analytics, history, caches,
report artifacts) resolves its default path through :func:`state_dir`, so one
environment variable decides where a process reads and writes:

* ``AGENT_BOM_STATE_DIR`` when set, otherwise ``~/.agent-bom``.

Demo estate mode must never read or write the operator's product data. When
``AGENT_BOM_DEMO_ESTATE`` is on, :func:`activate_demo_state_dir` pins the
process state dir to a dedicated demo directory (``AGENT_BOM_DEMO_STATE_DIR``,
default ``<product state dir>/demo-estate``) before any store resolves.
Explicit per-store overrides (``AGENT_BOM_DB``, ``AGENT_BOM_GRAPH_DB``,
``AGENT_BOM_POSTGRES_URL``, ...) remain the operator's explicit choice.
"""

from __future__ import annotations

import os
from pathlib import Path

STATE_DIR_ENV = "AGENT_BOM_STATE_DIR"
DEMO_STATE_DIR_ENV = "AGENT_BOM_DEMO_STATE_DIR"
DEMO_STATE_SUBDIR = "demo-estate"

_TRUTHY = {"1", "true", "yes", "on"}


def default_product_state_dir() -> Path:
    return Path.home() / ".agent-bom"


def state_dir() -> Path:
    """Return the directory this process keeps local data in (resolved per call)."""
    raw = (os.environ.get(STATE_DIR_ENV) or "").strip()
    return Path(raw).expanduser() if raw else default_product_state_dir()


def state_path(*parts: str) -> Path:
    return state_dir().joinpath(*parts)


def demo_estate_requested() -> bool:
    return os.environ.get("AGENT_BOM_DEMO_ESTATE", "").strip().lower() in _TRUTHY


def _same_path(a: Path, b: Path) -> bool:
    return a.expanduser().resolve() == b.expanduser().resolve()


# Explicit single-store path overrides. In demo mode none may point into the
# product state directory, or the demo would seed into operator data.
EXPLICIT_STORE_PATH_ENVS = (
    "AGENT_BOM_DB",
    "AGENT_BOM_GRAPH_DB",
    "AGENT_BOM_LOCAL_ANALYTICS_DB",
    "AGENT_BOM_DELIVERY_DB",
    "AGENT_BOM_POSTURE_WEBHOOK_OUTBOX_DB",
)


def _is_within(path: Path, root: Path) -> bool:
    return path.expanduser().resolve().is_relative_to(root.expanduser().resolve())


def _refuse_product_store_overrides(product_dirs: list[Path], demo_dir: Path) -> None:
    for var in EXPLICIT_STORE_PATH_ENVS:
        raw = (os.environ.get(var) or "").strip()
        if not raw or "://" in raw:
            continue
        candidate = Path(raw)
        if _is_within(candidate, demo_dir):
            continue
        if any(_is_within(candidate, product) for product in product_dirs):
            raise ValueError(
                f"{var}={raw} points into the product state directory while demo estate mode is on; "
                "demo data would mix with product data. Point it at a demo-only path or unset it."
            )


def activate_demo_state_dir() -> Path | None:
    """Pin this process's state dir to the dedicated demo directory.

    No-op outside demo mode. Idempotent: the chosen directory is recorded in
    ``AGENT_BOM_DEMO_STATE_DIR`` so a later call (a uvicorn worker re-import, or
    the API lifespan after the CLI already activated) resolves the same place
    instead of nesting. Raises ``ValueError`` if the demo directory would be the
    product state directory itself, or an explicit store path override
    (``EXPLICIT_STORE_PATH_ENVS``) points into the product state directory.
    """
    if not demo_estate_requested():
        return None
    pinned = (os.environ.get(DEMO_STATE_DIR_ENV) or "").strip()
    target = Path(pinned).expanduser() if pinned else state_dir() / DEMO_STATE_SUBDIR
    if _same_path(target, default_product_state_dir()):
        raise ValueError(
            f"{DEMO_STATE_DIR_ENV} must not be the product state directory ({default_product_state_dir()}); "
            "demo data would mix with product data."
        )
    product_dirs = [default_product_state_dir()]
    if not pinned:
        product_dirs.append(state_dir())
    _refuse_product_store_overrides(product_dirs, target)
    os.environ[DEMO_STATE_DIR_ENV] = str(target)
    os.environ[STATE_DIR_ENV] = str(target)
    return target


def demo_state_isolated() -> bool:
    """True when this process's state dir is the pinned demo directory."""
    pinned = (os.environ.get(DEMO_STATE_DIR_ENV) or "").strip()
    if not pinned:
        return False
    return _same_path(state_dir(), Path(pinned))


__all__ = [
    "DEMO_STATE_DIR_ENV",
    "DEMO_STATE_SUBDIR",
    "EXPLICIT_STORE_PATH_ENVS",
    "STATE_DIR_ENV",
    "activate_demo_state_dir",
    "default_product_state_dir",
    "demo_estate_requested",
    "demo_state_isolated",
    "state_dir",
    "state_path",
]
