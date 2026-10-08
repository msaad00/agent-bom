"""Every copy-paste ``docker compose -f <file>`` command names a file that exists.

The pilot manifest lives at ``deploy/docker-compose.pilot.yml``. A bare
``docker-compose.pilot.yml`` is only valid after the same page downloads it with
``curl ... -o docker-compose.pilot.yml``; anywhere else (a landing-page table
cell, a checkout instruction) it names a path that does not exist and the
command fails with "no such file".
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DOCS = (
    ROOT / "README.md",
    ROOT / "docs" / "registry" / "PYPI_README.md",
    ROOT / "docs" / "registry" / "DOCKER_HUB_README.md",
    ROOT / "docs" / "registry" / "DOCKER_HUB_UI_README.md",
    ROOT / "docs",
    ROOT / "site-docs",
    ROOT / "deploy",
)
_COMPOSE_FILE = re.compile(r"docker compose -f (\S+\.ya?ml)")


def _markdown_files() -> list[Path]:
    files: list[Path] = []
    for root in PUBLIC_DOCS:
        files.extend([root] if root.is_file() else sorted(root.rglob("*.md")))
    return files


def _downloaded_names(block: str) -> set[str]:
    return set(re.findall(r"curl [^\n]*-o (\S+\.ya?ml)", block))


def unresolvable_compose_paths(rel: str, text: str) -> list[str]:
    problems: list[str] = []
    for match in _COMPOSE_FILE.finditer(text):
        name = match.group(1)
        if name.startswith(("$", "<")) or (ROOT / name).is_file():
            continue
        if name in _downloaded_names(text[: match.start()]):
            continue
        problems.append(f"{rel}: `docker compose -f {name}` (no such file at the repository root)")
    return problems


def test_detector_flags_a_bare_pilot_path_outside_a_download_block() -> None:
    row = "| **Self-hosted** | `docker compose -f docker-compose.pilot.yml up -d` | dashboard |\n"
    assert unresolvable_compose_paths("x.md", row)
    downloaded = (
        "```bash\n"
        "curl -fsSL https://x/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml\n"
        "docker compose -f docker-compose.pilot.yml up -d\n"
        "```\n"
    )
    assert unresolvable_compose_paths("x.md", downloaded) == []
    assert unresolvable_compose_paths("x.md", downloaded + row) == []
    assert unresolvable_compose_paths("x.md", row + downloaded)
    assert unresolvable_compose_paths("x.md", "`docker compose -f deploy/docker-compose.pilot.yml up -d`") == []


def test_public_docs_name_compose_files_that_exist() -> None:
    problems: list[str] = []
    for path in _markdown_files():
        text = path.read_text(encoding="utf-8", errors="ignore")
        problems.extend(unresolvable_compose_paths(str(path.relative_to(ROOT)), text))
    assert problems == []
