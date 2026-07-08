"""API version surface helpers.

``API_V1_PREFIX`` is the single source of truth for the public REST version
segment. Domain route modules declare paths relative to this prefix; ``server``
mounts the aggregated v1 router once instead of scattering ``/v1`` literals
across ~30 route files (#3666).
"""

from __future__ import annotations

from fastapi import APIRouter

API_V1_PREFIX = "/v1"


def create_v1_api_router() -> APIRouter:
    """Return the parent router for all versioned public REST endpoints."""
    return APIRouter(prefix=API_V1_PREFIX)
