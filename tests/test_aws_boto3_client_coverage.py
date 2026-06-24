"""Guard: every boto3 client agent-bom instantiates is a valid AWS service.

boto3 is a single package (the ``aws`` extra), so there is no per-service
missing-distribution risk like the Azure SDKs. But a typo in a client name, or a
new service whose client predates the pinned boto3, would only surface as a live
runtime error. This test fails fast in CI instead: it scrapes every
``.client("<name>")`` the cloud code uses and asserts each is a real service in
the installed boto3 — which also proves the ``boto3>=`` pin is new enough.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_CLOUD_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud"


def _instantiated_clients() -> set[str]:
    names: set[str] = set()
    for py in _CLOUD_DIR.glob("*.py"):
        for m in re.findall(r"""\.client\(\s*['"]([a-z0-9-]+)['"]""", py.read_text()):
            names.add(m)
    return names


def test_every_boto3_client_used_is_a_valid_service() -> None:
    boto3 = pytest.importorskip("boto3")
    available = set(boto3.Session().get_available_services())
    used = _instantiated_clients()
    assert used, "no boto3 .client() calls found — scraper regex may be stale"
    missing = sorted(c for c in used if c not in available)
    assert not missing, (
        f"boto3 {boto3.__version__} has no client for: {missing} — typo, or bump the boto3 pin in the aws extra to a version that ships it"
    )
