"""Shipped images take distro security fixes at build time, not only at base bumps.

A pinned base digest freezes OS packages. Fixes published after that digest
(for example Alpine ``zlib 1.3.2-r1``) reach a release only through the final
stage's package upgrade, so every shipped runtime stage must keep one.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHIPPED_DOCKERFILES = (
    "Dockerfile",
    "ui/Dockerfile",
    "integrations/glama/Dockerfile",
    "deploy/docker/Dockerfile.collector",
    "deploy/docker/Dockerfile.mcp",
    "deploy/docker/Dockerfile.native-app",
    "deploy/docker/Dockerfile.runtime",
    "deploy/docker/Dockerfile.snowpark",
    "deploy/docker/Dockerfile.sse",
)
_UPGRADE = {
    "alpine": re.compile(r"\bapk upgrade --no-cache --available\b"),
    "debian": re.compile(r"\bapt-get (?:-y )?upgrade\b"),
}


def _final_stage(text: str) -> tuple[str, str]:
    stages = re.split(r"(?m)^FROM\s+", text)
    final = stages[-1]
    base = final.split(None, 1)[0]
    family = "alpine" if "alpine" in base else "debian"
    return family, final


@pytest.mark.parametrize("relative", SHIPPED_DOCKERFILES)
def test_final_stage_upgrades_os_packages(relative: str) -> None:
    family, final = _final_stage((ROOT / relative).read_text(encoding="utf-8"))
    assert _UPGRADE[family].search(final), f"{relative}: final {family} stage must upgrade OS packages"


def test_guard_rejects_a_final_stage_without_upgrade() -> None:
    dockerfile = (
        "FROM python:3-alpine AS builder\nRUN apk upgrade --no-cache --available\nFROM python:3-alpine\nRUN apk add --no-cache git\n"
    )
    family, final = _final_stage(dockerfile)
    assert family == "alpine"
    assert not _UPGRADE[family].search(final)


def test_every_shipped_dockerfile_is_covered() -> None:
    tracked = {
        str(path.relative_to(ROOT))
        for pattern in ("Dockerfile", "ui/Dockerfile", "integrations/*/Dockerfile", "deploy/docker/Dockerfile.*")
        for path in ROOT.glob(pattern)
    }
    assert tracked == set(SHIPPED_DOCKERFILES)
