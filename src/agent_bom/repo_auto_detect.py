"""Auto-detect static scan surfaces in a project or cloned repository root.

Used by CLI ``--project`` / ``--repo`` so users do not need ``--jupyter``,
``--code``, ``--tf-dir``, etc. when the repo already contains those artifacts.
Explicit flags always win; auto-detect only fills empty targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from agent_bom.iac import is_iac_file
from agent_bom.traversal import iter_discovery_files

_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "site-packages",
        ".tox",
        ".eggs",
        ".mypy_cache",
        ".ipynb_checkpoints",
    }
)

_SAST_EXTENSIONS = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php", ".cs"})
_PYTHON_MANIFESTS = frozenset(
    {
        "requirements.txt",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "Pipfile",
        "Pipfile.lock",
        "setup.py",
        "setup.cfg",
    }
)

_CODEOWNERS_LOCATIONS = (
    Path(".github/CODEOWNERS"),
    Path("CODEOWNERS"),
    Path("docs/CODEOWNERS"),
)


def load_codeowners(root: Path) -> dict[str, str]:
    """Return stable path-prefix ownership from the repository CODEOWNERS.

    GitHub searches the three canonical locations in order and uses only the
    first file found.  The ASPM graph needs joinable application prefixes, so
    patterns without a stable directory prefix (for example ``*.md``) are
    omitted; a repository-wide ``*`` rule is retained as the empty prefix.
    Within a file, later rules replace earlier rules for the same prefix.
    """
    if not root.is_dir():
        return {}
    owners_file = next((root / rel for rel in _CODEOWNERS_LOCATIONS if (root / rel).is_file()), None)
    if owners_file is None:
        return {}

    owners: dict[str, str] = {}
    try:
        lines = owners_file.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {}
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern, owner_values = parts[0], [value for value in parts[1:] if value.startswith("@")]
        if not owner_values:
            continue
        if pattern in {"*", "/*", "/**", "/**/*"}:
            prefix = ""
        else:
            normalized = pattern.lstrip("/").rstrip("/")
            wildcard_at = min((normalized.find(char) for char in "*?[" if char in normalized), default=-1)
            stable = normalized if wildcard_at < 0 else normalized[:wildcard_at]
            prefix = stable.rstrip("/")
            if not prefix or "/" not in normalized and wildcard_at >= 0:
                continue
        owners[prefix] = ", ".join(owner_values)
    return owners


@dataclass(frozen=True)
class RepoStaticSurface:
    """One auto-detected static scan surface shared by CLI, API repo-tree, and UI catalog."""

    id: str
    label: str
    cli_auto_key: str | None = None
    api_repo_tree: bool = False
    requires_semgrep: bool = False


REPO_STATIC_SURFACES: tuple[RepoStaticSurface, ...] = (
    RepoStaticSurface("jupyter", "Jupyter notebooks", cli_auto_key="jupyter", api_repo_tree=True),
    RepoStaticSurface("sast", "SAST / code paths", cli_auto_key="sast", api_repo_tree=True, requires_semgrep=True),
    RepoStaticSurface("prompts", "Prompt templates", cli_auto_key="prompts", api_repo_tree=False),
    RepoStaticSurface("terraform", "Terraform & cloud AI infra", cli_auto_key="terraform", api_repo_tree=True),
    RepoStaticSurface("github_actions", "CI/CD pipelines", cli_auto_key="github_actions", api_repo_tree=True),
    RepoStaticSurface("python_agents", "Python agent frameworks", cli_auto_key="python_agents", api_repo_tree=True),
    RepoStaticSurface("ai_inventory", "AI SDK / observability inventory", cli_auto_key="ai_inventory", api_repo_tree=True),
    RepoStaticSurface("skills", "Skills & instruction files", api_repo_tree=True),
    RepoStaticSurface("iac", "IaC & deployment configs", cli_auto_key="iac", api_repo_tree=True),
    RepoStaticSurface("dependencies", "Lockfiles & manifests", api_repo_tree=True),
    RepoStaticSurface("secrets", "Secrets & credentials", api_repo_tree=True),
    RepoStaticSurface("weak_crypto", "Weak cryptography", api_repo_tree=True),
)


def repo_static_surface_catalog() -> list[dict[str, str | bool]]:
    """JSON-serializable catalog for docs, UI parity notes, and API docstrings."""
    return [
        {
            "id": surface.id,
            "label": surface.label,
            "cli_auto_key": surface.cli_auto_key or "",
            "api_repo_tree": surface.api_repo_tree,
            "requires_semgrep": surface.requires_semgrep,
        }
        for surface in REPO_STATIC_SURFACES
    ]


def repo_static_surface_summary() -> str:
    """One-line summary for scan_cloned_repo_tree docstrings."""
    api_surfaces = [surface.label for surface in REPO_STATIC_SURFACES if surface.api_repo_tree]
    return ", ".join(api_surfaces)


@dataclass
class ProjectScanTargets:
    jupyter_dirs: tuple[str, ...]
    code_paths: tuple[str, ...]
    scan_prompts: bool
    tf_dirs: tuple[str, ...]
    gha_path: str | None
    agent_projects: tuple[str, ...]
    ai_inventory_paths: tuple[str, ...] = ()
    iac_paths: tuple[str, ...] = ()
    auto_enabled: list[str] = field(default_factory=list)


_TREE_SURFACES = frozenset({"jupyter", "sast", "terraform", "iac", "python_source"})


def _tree_surface_hits(path: Path, root: Path, wanted: frozenset[str]) -> set[str]:
    suffix = path.suffix.lower()
    hits: set[str] = set()
    if "jupyter" in wanted and suffix == ".ipynb":
        hits.add("jupyter")
    if "sast" in wanted and suffix in _SAST_EXTENSIONS:
        hits.add("sast")
    if "terraform" in wanted and suffix in {".tf", ".tfvars"}:
        hits.add("terraform")
    if "python_source" in wanted and suffix == ".py" and path.name != "__init__.py":
        hits.add("python_source")
    if "iac" in wanted and is_iac_file(path, root):
        hits.add("iac")
    return hits


def detect_tree_surfaces(root: Path, wanted: frozenset[str] = _TREE_SURFACES) -> frozenset[str]:
    """Return which of *wanted* tree-content surfaces exist under *root*, in one walk.

    Detection walks the whole (pruned) tree under the shared traversal bound and
    stops as soon as every wanted surface is found. A per-probe file budget
    would both miss surfaces deep in a normal-sized repository and report the
    probe itself as a coverage gap, marking an otherwise complete scan partial.
    """
    found: set[str] = set()
    if not wanted or not root.is_dir():
        return frozenset()
    # Vendored/generated dirs and nested VCS worktrees (e.g. ``.claude/worktrees``)
    # are pruned during the walk, so detection never descends duplicated checkouts.
    for path in iter_discovery_files(root, extra_skip_dirs=_SKIP_DIRS):
        found |= _tree_surface_hits(path, root, wanted - found)
        if found >= wanted:
            break
    return frozenset(found)


def project_has_notebooks(root: Path) -> bool:
    return "jupyter" in detect_tree_surfaces(root, frozenset({"jupyter"}))


def project_has_sast_targets(root: Path) -> bool:
    return "sast" in detect_tree_surfaces(root, frozenset({"sast"}))


def project_has_prompt_templates(root: Path) -> bool:
    from agent_bom.parsers.prompt_scanner import discover_prompt_files

    return bool(discover_prompt_files(root))


def project_has_terraform(root: Path) -> bool:
    return "terraform" in detect_tree_surfaces(root, frozenset({"terraform"}))


def project_has_iac(root: Path) -> bool:
    """True when the tree holds any file the IaC scanners would dispatch on.

    Delegates to :func:`agent_bom.iac.is_iac_file` so detection can never
    disagree with what ``scan_iac_with_context`` actually scans, and walks
    recursively — IaC normally lives under ``infra/``, ``deploy/`` or
    ``charts/``, not at the repo root.
    """
    return "iac" in detect_tree_surfaces(root, frozenset({"iac"}))


def project_has_github_actions(root: Path) -> bool:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return False
    return any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))


def _has_python_manifest(root: Path) -> bool:
    return root.is_dir() and any((root / name).exists() for name in _PYTHON_MANIFESTS)


def project_has_python_agent_surface(root: Path) -> bool:
    return _has_python_manifest(root) or "python_source" in detect_tree_surfaces(root, frozenset({"python_source"}))


def semgrep_available() -> bool:
    from agent_bom.sast import _semgrep_available

    return _semgrep_available()


def expand_project_scan_targets(
    project: str | Path,
    *,
    jupyter_dirs: tuple[str, ...] = (),
    code_paths: tuple[str, ...] = (),
    scan_prompts: bool = False,
    tf_dirs: tuple[str, ...] = (),
    gha_path: str | None = None,
    agent_projects: tuple[str, ...] = (),
    ai_inventory_paths: tuple[str, ...] = (),
    iac_paths: tuple[str, ...] = (),
) -> ProjectScanTargets:
    """Fill empty scan targets from project tree content."""
    root = Path(project).resolve()
    auto: list[str] = []
    out_prompts = scan_prompts
    out_tf = tf_dirs
    out_gha = gha_path
    out_agents = agent_projects
    out_ai_inventory = ai_inventory_paths
    out_iac = iac_paths

    wanted = {
        "jupyter": not jupyter_dirs,
        "sast": not code_paths and semgrep_available(),
        "terraform": not tf_dirs,
        "iac": not iac_paths,
        "python_source": bool(not agent_projects or not ai_inventory_paths) and not _has_python_manifest(root),
    }
    found = detect_tree_surfaces(root, frozenset(name for name, needed in wanted.items() if needed))
    has_python_surface = _has_python_manifest(root) or "python_source" in found
    out_jupyter = (str(root),) if "jupyter" in found else jupyter_dirs
    out_code = (str(root),) if "sast" in found else code_paths
    auto.extend(name for name in ("jupyter", "sast") if name in found)

    if not scan_prompts and project_has_prompt_templates(root):
        out_prompts = True
        auto.append("prompts")

    if "terraform" in found:
        out_tf = (str(root),)
        auto.append("terraform")

    # The IaC security rules run on the whole tree, exactly as the API repo-tree
    # scan does. Without this the CLI reported ``terraform`` as a scan source
    # while every misconfiguration rule stayed unexecuted.
    if "iac" in found:
        out_iac = (str(root),)
        auto.append("iac")

    if not gha_path and project_has_github_actions(root):
        out_gha = str(root)
        auto.append("github_actions")

    if not agent_projects and has_python_surface:
        out_agents = (str(root),)
        auto.append("python_agents")

    # Same surface as python agents: SDK/obs imports (LangChain, Langfuse, …)
    # become first-class AI BOM framework nodes when inventory is enabled.
    if not ai_inventory_paths and has_python_surface:
        out_ai_inventory = (str(root),)
        auto.append("ai_inventory")

    return ProjectScanTargets(
        jupyter_dirs=out_jupyter,
        code_paths=out_code,
        scan_prompts=out_prompts,
        tf_dirs=out_tf,
        gha_path=out_gha,
        agent_projects=out_agents,
        ai_inventory_paths=out_ai_inventory,
        iac_paths=out_iac,
        auto_enabled=auto,
    )
