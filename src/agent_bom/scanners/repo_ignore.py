"""Git-compatible repository ignore semantics for scanner traversal.

Discovery previously excluded paths with a single hardcoded directory-name
allowlist (``traversal.VENDOR_SKIP_DIRS``). Any ignored directory whose *name*
was absent from that list was scanned in full, so a gitignored browser
automation cache produced hundreds of CRITICAL "hardcoded credential" findings
from throwaway artifacts. Growing the allowlist by one entry per incident does
not converge: the repository already states what it considers uninteresting.

This module reads that statement. It honours the ``.gitignore`` rules Git
itself would apply — nested files, negation, anchoring, directory-only rules —
plus a scanner-specific ``.agentbomignore`` with the same pattern syntax.

Precedence, most specific last::

    root .gitignore  <  nested .gitignore (deeper wins)  <  .agentbomignore

``.agentbomignore`` is evaluated last *by design*: it is the scanner's own
override, so it can both add exclusions Git does not have and re-include
(``!pattern``) a path Git ignores but the scanner must still inspect.

One Git rule is deliberately reproduced because it is load-bearing for
traversal cost as well as correctness: **a file cannot be re-included once one
of its parent directories is excluded.** That is what lets an excluded
directory be pruned during the walk instead of enumerated and filtered.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from pathspec import PathSpec

GITIGNORE_FILENAME = ".gitignore"
SCANNER_IGNORE_FILENAME = ".agentbomignore"

# A single ignore file can be hostile or accidentally enormous; cap what we
# compile so a pathological repository cannot stall discovery.
_MAX_PATTERNS_PER_FILE = 5_000
_GIT_QUERY_TIMEOUT_SECONDS = 5


def _inside_git_checkout(path: Path) -> bool:
    """Best-effort checkout detection when Git itself cannot answer."""
    return any((candidate / ".git").exists() for candidate in (path, *path.parents))


def _git_tracked_paths(root: Path) -> tuple[frozenset[str], frozenset[str], bool]:
    """Return tracked files/directories relative to *root*.

    Git ignore rules only apply to untracked paths. If a checkout is visible but
    Git cannot enumerate its index, disable .gitignore exclusions rather than
    risk suppressing a committed secret. Explicit .agentbomignore rules remain
    available because they are scanner policy, not inferred Git state.
    """
    command = ["git", "-C", str(root), "rev-parse", "--show-toplevel"]
    try:
        top_level = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=_GIT_QUERY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset(), frozenset(), _inside_git_checkout(root)

    if top_level.returncode != 0:
        return frozenset(), frozenset(), _inside_git_checkout(root)

    repository_root = Path(top_level.stdout.strip()).resolve()
    try:
        listed = subprocess.run(
            ["git", "-C", str(repository_root), "ls-files", "-z", "--cached"],
            check=False,
            capture_output=True,
            timeout=_GIT_QUERY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return frozenset(), frozenset(), True
    if listed.returncode != 0:
        return frozenset(), frozenset(), True

    tracked_files: set[str] = set()
    tracked_dirs: set[str] = set()
    for raw_path in listed.stdout.split(b"\0"):
        if not raw_path:
            continue
        try:
            repository_relative = raw_path.decode("utf-8", errors="surrogateescape")
            scan_relative = (repository_root / repository_relative).relative_to(root).as_posix()
        except ValueError:
            continue
        tracked_files.add(scan_relative)
        tracked_dirs.update(parent.as_posix() for parent in PurePosixPath(scan_relative).parents if parent.as_posix() != ".")
    return frozenset(tracked_files), frozenset(tracked_dirs), False


def _compile(lines: list[str]) -> PathSpec | None:
    patterns = [line for line in lines[:_MAX_PATTERNS_PER_FILE] if line.strip() and not line.lstrip().startswith("#")]
    if not patterns:
        return None
    try:
        # "gitignore" is pathspec's current Git-semantics factory; the older
        # "gitwildmatch" name is deprecated in pathspec >= 1.1.
        return PathSpec.from_lines("gitignore", patterns)
    except Exception:
        # A malformed ignore file must degrade to "ignores nothing", never
        # abort the scan — refusing to scan is a worse failure than scanning
        # a path the user meant to exclude.
        return None


def _read(path: Path) -> list[str] | None:
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


@dataclass
class _Layer:
    """One ignore file, scoped to the directory that contains it."""

    # Directory the file lives in, relative to the scan root ("" at the root).
    base: str
    spec: PathSpec
    # Scanner override files are consulted after every .gitignore layer.
    is_override: bool = False


@dataclass
class RepositoryIgnore:
    """Ignore rules for one scan root, resolved lazily per directory."""

    root: Path
    _layers: list[_Layer] = field(default_factory=list)
    _loaded_dirs: set[str] = field(default_factory=set)
    ignored_count: int = 0
    _tracked_files: frozenset[str] = frozenset()
    _tracked_dirs: frozenset[str] = frozenset()
    _gitignore_fail_closed: bool = False

    @classmethod
    def for_root(cls, root: Path) -> "RepositoryIgnore":
        resolved_root = Path(root).resolve()
        tracked_files, tracked_dirs, gitignore_fail_closed = _git_tracked_paths(resolved_root)
        instance = cls(
            root=resolved_root,
            _tracked_files=tracked_files,
            _tracked_dirs=tracked_dirs,
            _gitignore_fail_closed=gitignore_fail_closed,
        )
        instance._load_dir("")
        return instance

    # ── loading ──────────────────────────────────────────────────────────────

    def _load_dir(self, rel_dir: str) -> None:
        """Compile the ignore files that live in *rel_dir* (once)."""
        if rel_dir in self._loaded_dirs:
            return
        self._loaded_dirs.add(rel_dir)
        directory = self.root / rel_dir if rel_dir else self.root
        for filename, is_override in ((GITIGNORE_FILENAME, False), (SCANNER_IGNORE_FILENAME, True)):
            lines = _read(directory / filename)
            if lines is None:
                continue
            spec = _compile(lines)
            if spec is not None:
                self._layers.append(_Layer(base=rel_dir, spec=spec, is_override=is_override))

    def _ordered_layers(self) -> list[_Layer]:
        """Least specific first: shallow .gitignore → deep .gitignore → overrides.

        Sorting by depth reproduces Git's "deeper file wins"; keeping every
        override last is this scanner's documented addition.
        """
        return sorted(
            self._layers,
            key=lambda layer: (layer.is_override, len(PurePosixPath(layer.base).parts) if layer.base else 0),
        )

    # ── matching ─────────────────────────────────────────────────────────────

    def _match(self, rel_path: str, *, is_dir: bool) -> bool:
        """Return True when the last matching rule excludes *rel_path*."""
        candidate = f"{rel_path}/" if is_dir and not rel_path.endswith("/") else rel_path
        excluded = False
        ordered_layers = self._ordered_layers()
        for layer in (item for item in ordered_layers if not item.is_override):
            if self._gitignore_fail_closed:
                break
            scoped = self._scope(candidate, layer.base)
            if scoped is None:
                continue
            # ``check_file`` reports the *last* matching pattern, which is how
            # negation is resolved inside a single file.
            result = layer.spec.check_file(scoped)
            if result.include is None:
                continue
            excluded = bool(result.include)

        # Git never ignores an already tracked file. Likewise, an ignored
        # directory cannot be pruned when it contains tracked descendants.
        # Scanner-specific overrides remain authoritative and are evaluated
        # afterward, so .agentbomignore may intentionally exclude tracked data.
        if (is_dir and rel_path in self._tracked_dirs) or (not is_dir and rel_path in self._tracked_files):
            excluded = False

        for layer in (item for item in ordered_layers if item.is_override):
            scoped = self._scope(candidate, layer.base)
            if scoped is None:
                continue
            result = layer.spec.check_file(scoped)
            if result.include is None:
                continue
            excluded = bool(result.include)
        return excluded

    @staticmethod
    def _scope(rel_path: str, base: str) -> str | None:
        """Re-express *rel_path* relative to the directory owning a layer."""
        if not base:
            return rel_path
        prefix = f"{base}/"
        if rel_path == base or rel_path == prefix:
            return ""
        if not rel_path.startswith(prefix):
            return None
        return rel_path[len(prefix) :]

    def is_ignored_dir(self, rel_dir: str) -> bool:
        """True when a directory subtree can be pruned entirely."""
        if not rel_dir:
            # The root was named explicitly by the caller; it is always walked.
            return False
        return self._match(rel_dir, is_dir=True)

    def is_ignored_file(self, rel_path: str) -> bool:
        if not rel_path:
            return False
        return self._match(rel_path, is_dir=False)

    def enter_directory(self, rel_dir: str) -> None:
        """Load ignore files for a directory the walk is about to descend into."""
        self._load_dir(rel_dir)

    def note_ignored(self, count: int = 1) -> None:
        self.ignored_count += count


__all__ = [
    "GITIGNORE_FILENAME",
    "SCANNER_IGNORE_FILENAME",
    "RepositoryIgnore",
]
