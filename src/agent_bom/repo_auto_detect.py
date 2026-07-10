"""Auto-detect static scan surfaces in a project or cloned repository root.

Used by CLI ``--project`` / ``--repo`` so users do not need ``--jupyter``,
``--code``, ``--tf-dir``, etc. when the repo already contains those artifacts.
Explicit flags always win; auto-detect only fills empty targets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

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
    RepoStaticSurface("iac", "IaC & deployment configs", api_repo_tree=True),
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
    auto_enabled: list[str] = field(default_factory=list)


def _walk_limited(root: Path, *, max_files: int = 4000) -> list[Path]:
    files: list[Path] = []
    if not root.is_dir():
        return files
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        files.append(path)
        if len(files) >= max_files:
            break
    return files


def project_has_notebooks(root: Path) -> bool:
    if not root.is_dir():
        return False
    for path in root.rglob("*.ipynb"):
        if ".ipynb_checkpoints" in path.parts:
            continue
        return True
    return False


def project_has_sast_targets(root: Path) -> bool:
    for path in _walk_limited(root, max_files=500):
        if path.suffix.lower() in _SAST_EXTENSIONS:
            return True
    return False


def project_has_prompt_templates(root: Path) -> bool:
    from agent_bom.parsers.prompt_scanner import discover_prompt_files

    return bool(discover_prompt_files(root))


def project_has_terraform(root: Path) -> bool:
    if not root.is_dir():
        return False
    for pattern in ("*.tf", "*.tfvars"):
        if any(root.rglob(pattern)):
            return True
    return False


def project_has_github_actions(root: Path) -> bool:
    workflows = root / ".github" / "workflows"
    if not workflows.is_dir():
        return False
    return any(workflows.glob("*.yml")) or any(workflows.glob("*.yaml"))


def project_has_python_agent_surface(root: Path) -> bool:
    if not root.is_dir():
        return False
    for name in _PYTHON_MANIFESTS:
        if (root / name).exists():
            return True
    for path in _walk_limited(root, max_files=800):
        if path.suffix.lower() == ".py" and path.name != "__init__.py":
            return True
    return False


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
) -> ProjectScanTargets:
    """Fill empty scan targets from project tree content."""
    root = Path(project).resolve()
    auto: list[str] = []
    out_jupyter = jupyter_dirs
    out_code = code_paths
    out_prompts = scan_prompts
    out_tf = tf_dirs
    out_gha = gha_path
    out_agents = agent_projects
    out_ai_inventory = ai_inventory_paths

    if not jupyter_dirs and project_has_notebooks(root):
        out_jupyter = (str(root),)
        auto.append("jupyter")

    if not code_paths and semgrep_available() and project_has_sast_targets(root):
        out_code = (str(root),)
        auto.append("sast")

    if not scan_prompts and project_has_prompt_templates(root):
        out_prompts = True
        auto.append("prompts")

    if not tf_dirs and project_has_terraform(root):
        out_tf = (str(root),)
        auto.append("terraform")

    if not gha_path and project_has_github_actions(root):
        out_gha = str(root)
        auto.append("github_actions")

    if not agent_projects and project_has_python_agent_surface(root):
        out_agents = (str(root),)
        auto.append("python_agents")

    # Same surface as python agents: SDK/obs imports (LangChain, Langfuse, …)
    # become first-class AI BOM framework nodes when inventory is enabled.
    if not ai_inventory_paths and project_has_python_agent_surface(root):
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
        auto_enabled=auto,
    )
