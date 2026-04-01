"""Deterministic bundle identity for skill and instruction files."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.finding import stable_id

_MARKDOWN_LINK_RE = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
_LOCAL_PATH_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:\./|\.\./)?(?:[\w.-]+/)*[\w.-]+\.(?:py|sh|js|ts|tsx|jsx|json|ya?ml|toml|ini|cfg|txt|md|sql|csv|svg|png|jpg|jpeg)"
)
_URL_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*://")


@dataclass(frozen=True)
class SkillBundleFile:
    """One file included in a deterministic skill bundle."""

    path: str
    sha256: str
    size: int
    role: str = "referenced"


@dataclass(frozen=True)
class SkillBundle:
    """Stable bundle identity for a skill file and its local references."""

    stable_id: str
    sha256: str
    root: str
    file_count: int
    referenced_file_count: int
    files: list[SkillBundleFile] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize bundle metadata to JSON-compatible data."""
        return {
            "stable_id": self.stable_id,
            "sha256": self.sha256,
            "root": self.root,
            "file_count": self.file_count,
            "referenced_file_count": self.referenced_file_count,
            "files": [
                {
                    "path": entry.path,
                    "sha256": entry.sha256,
                    "size": entry.size,
                    "role": entry.role,
                }
                for entry in self.files
            ],
        }


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _candidate_local_refs(content: str) -> set[str]:
    refs: set[str] = set()
    for match in _MARKDOWN_LINK_RE.finditer(content):
        candidate = match.group(1).strip()
        if candidate and not _URL_SCHEME_RE.match(candidate) and not candidate.startswith(("#", "mailto:", "data:")):
            refs.add(candidate)
    for match in _LOCAL_PATH_TOKEN_RE.finditer(content):
        candidate = match.group(0).strip()
        if candidate and not candidate.startswith(("/", "~")):
            refs.add(candidate)
    return refs


def _resolve_local_refs(primary_path: Path, content: str) -> list[Path]:
    base = primary_path.parent
    refs: list[Path] = []
    seen: set[Path] = set()
    for ref in sorted(_candidate_local_refs(content)):
        candidate = (base / ref).resolve()
        if candidate.is_file() and candidate != primary_path.resolve() and candidate not in seen:
            seen.add(candidate)
            refs.append(candidate)
    return refs


def build_skill_bundle(path: Path, content: str | None = None) -> SkillBundle:
    """Build a deterministic bundle identity for one skill file."""
    primary = path.resolve()
    if content is None:
        content = primary.read_text(encoding="utf-8", errors="replace")
    included = [primary, *_resolve_local_refs(primary, content)]
    if len(included) == 1:
        root = primary.parent
    else:
        root = Path(os.path.commonpath([str(p.parent) for p in included]))

    files: list[SkillBundleFile] = []
    manifest_rows: list[dict[str, object]] = []
    for included_path in sorted(included, key=lambda p: os.path.relpath(p, root).replace(os.sep, "/")):
        role = "primary" if included_path == primary else "referenced"
        rel_path = os.path.relpath(included_path, root).replace(os.sep, "/")
        file_hash = _sha256_file(included_path)
        size = included_path.stat().st_size
        files.append(SkillBundleFile(path=rel_path, sha256=file_hash, size=size, role=role))
        manifest_rows.append({"path": rel_path, "sha256": file_hash, "size": size, "role": role})

    manifest = json.dumps(manifest_rows, sort_keys=True, separators=(",", ":"))
    bundle_hash = hashlib.sha256(manifest.encode("utf-8")).hexdigest()
    return SkillBundle(
        stable_id=stable_id("skill-bundle", bundle_hash),
        sha256=bundle_hash,
        root=str(root),
        file_count=len(files),
        referenced_file_count=max(0, len(files) - 1),
        files=files,
    )
