"""Parse package dependencies from MCP server directories."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from rich.console import Console

from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
from agent_bom.models import MCPServer, Package
from agent_bom.parsers.base import InventoryParserRegistration

# Re-export Go/Maven/Cargo/Gradle/conda/uvx parsers for backward compatibility
from agent_bom.parsers.compiled_parsers import (  # noqa: F401
    _parse_go_mod_requires,
    _parse_pom_modules,
    detect_uvx_package,
    parse_cargo_packages,
    parse_conda_packages,
    parse_go_packages,
    parse_go_workspace,
    parse_gradle_packages,
    parse_maven_packages,
)

# Re-export .NET/NuGet parsers
from agent_bom.parsers.dotnet_parsers import parse_nuget_packages  # noqa: F401

# Re-export Node.js parsers for backward compatibility
from agent_bom.parsers.node_parsers import (  # noqa: F401
    _npm_purl,
    detect_npx_package,
    parse_bun_packages,
    parse_npm_packages,
    parse_pnpm_lock,
    parse_yarn_lock,
)

# Re-export OS package parsers (dpkg/rpm/apk — live system and mounted snapshots)
from agent_bom.parsers.os_parsers import (  # noqa: F401
    parse_apk_packages,
    parse_dpkg_packages,
    parse_rpm_packages,
    scan_os_packages,
)
from agent_bom.parsers.php_parsers import parse_php_packages  # noqa: F401

# Re-export Python parsers for backward compatibility
from agent_bom.parsers.python_parsers import (  # noqa: F401
    parse_conda_environment,
    parse_pip_compile_inputs,
    parse_pip_environment,
    parse_pip_packages,
    parse_poetry_lock,
    parse_uv_lock,
)

# Re-export Ruby, PHP, and Swift parsers
from agent_bom.parsers.ruby_parsers import parse_ruby_packages  # noqa: F401
from agent_bom.parsers.swift_parsers import parse_swift_packages  # noqa: F401

_ENTRY_POINT_GROUP = "agent_bom.inventory_parsers"


_BUILTIN_INVENTORY_PARSERS: dict[str, tuple[str, str, tuple[str, ...]]] = {
    "npm": ("agent_bom.parsers.node_parsers", "parse_npm_packages", ("package.json", "package-lock.json")),
    "yarn": ("agent_bom.parsers.node_parsers", "parse_yarn_lock", ("yarn.lock",)),
    "pnpm": ("agent_bom.parsers.node_parsers", "parse_pnpm_lock", ("pnpm-lock.yaml",)),
    "bun": ("agent_bom.parsers.node_parsers", "parse_bun_packages", ("bun.lockb", "bun.lock")),
    "pip": ("agent_bom.parsers.python_parsers", "parse_pip_packages", ("requirements.txt", "pyproject.toml", "poetry.lock", "uv.lock")),
    "pip_compile": ("agent_bom.parsers.python_parsers", "parse_pip_compile_inputs", ("requirements.in",)),
    "conda_environment": ("agent_bom.parsers.python_parsers", "parse_conda_environment", ("environment.yml", "environment.yaml")),
    "conda": ("agent_bom.parsers.compiled_parsers", "parse_conda_packages", ("conda-meta",)),
    "go": ("agent_bom.parsers.compiled_parsers", "parse_go_packages", ("go.mod", "go.sum")),
    "cargo": ("agent_bom.parsers.compiled_parsers", "parse_cargo_packages", ("Cargo.toml", "Cargo.lock")),
    "maven": ("agent_bom.parsers.compiled_parsers", "parse_maven_packages", ("pom.xml",)),
    "gradle": ("agent_bom.parsers.compiled_parsers", "parse_gradle_packages", ("build.gradle", "build.gradle.kts")),
    "nuget": ("agent_bom.parsers.dotnet_parsers", "parse_nuget_packages", ("*.csproj", "packages.lock.json")),
    "ruby": ("agent_bom.parsers.ruby_parsers", "parse_ruby_packages", ("Gemfile", "Gemfile.lock")),
    "php": ("agent_bom.parsers.php_parsers", "parse_php_packages", ("composer.json", "composer.lock")),
    "swift": ("agent_bom.parsers.swift_parsers", "parse_swift_packages", ("Package.swift", "Package.resolved")),
    "apk": ("agent_bom.parsers.os_parsers", "parse_apk_packages", ("lib/apk/db/installed",)),
    "dpkg": ("agent_bom.parsers.os_parsers", "parse_dpkg_packages", ("var/lib/dpkg/status",)),
    "rpm": ("agent_bom.parsers.os_parsers", "parse_rpm_packages", ("var/lib/rpm",)),
}

_INVENTORY_PARSER_REGISTRY: dict[str, InventoryParserRegistration] = {}
_INVENTORY_PARSER_REGISTRY_WARNINGS: list[str] = []
_INVENTORY_PARSER_REGISTRY_LOADED = False


def _parser_capabilities() -> ExtensionCapabilities:
    return ExtensionCapabilities(
        scan_modes=("inventory",),
        required_scopes=("local_project_read",),
        outbound_destinations=(),
        data_boundary="local_manifest_read_only",
        network_access=False,
        guarantees=("read_only", "local_files_only"),
    )


def _registration_for_inventory_parser(
    name: str,
    module: str,
    parse_attr: str,
    manifest_names: tuple[str, ...],
    *,
    source: str = "builtin",
) -> InventoryParserRegistration:
    return InventoryParserRegistration(
        name=name,
        module=module,
        capabilities=_parser_capabilities(),
        source=source,
        parse_attr=parse_attr,
        manifest_names=manifest_names,
    )


def builtin_inventory_parser_registrations() -> list[InventoryParserRegistration]:
    """Return built-in package inventory parser registrations."""

    return [
        _registration_for_inventory_parser(name, module, parse_attr, manifest_names)
        for name, (module, parse_attr, manifest_names) in _BUILTIN_INVENTORY_PARSERS.items()
    ]


def _coerce_inventory_parser_registration(value: Any, entry_point_name: str) -> InventoryParserRegistration:
    if isinstance(value, InventoryParserRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("inventory parser registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    return InventoryParserRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=str(getattr(value, "source", "entry_point")),
        discover_attr=str(getattr(value, "discover_attr", "discover")),
        parse_attr=str(getattr(value, "parse_attr", "parse")),
        manifest_names=tuple(str(item) for item in getattr(value, "manifest_names", ())),
    )


def register_inventory_parser(registration: InventoryParserRegistration) -> None:
    """Register an inventory parser with capability metadata."""

    _INVENTORY_PARSER_REGISTRY[registration.name] = registration


def _ensure_inventory_parser_registry_loaded() -> None:
    global _INVENTORY_PARSER_REGISTRY_LOADED
    if _INVENTORY_PARSER_REGISTRY_LOADED:
        return
    for registration in builtin_inventory_parser_registrations():
        register_inventory_parser(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_inventory_parser_registration,
        warnings=_INVENTORY_PARSER_REGISTRY_WARNINGS,
    ):
        register_inventory_parser(registration)
    _INVENTORY_PARSER_REGISTRY_LOADED = True


def list_registered_inventory_parsers() -> list[InventoryParserRegistration]:
    """Return registered inventory parsers with capability declarations."""

    _ensure_inventory_parser_registry_loaded()
    return [_INVENTORY_PARSER_REGISTRY[name] for name in sorted(_INVENTORY_PARSER_REGISTRY)]


def inventory_parser_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_inventory_parser_registry_loaded()
    return list(_INVENTORY_PARSER_REGISTRY_WARNINGS)


def _reset_inventory_parser_registry_for_tests() -> None:
    _INVENTORY_PARSER_REGISTRY.clear()
    _INVENTORY_PARSER_REGISTRY_WARNINGS.clear()
    global _INVENTORY_PARSER_REGISTRY_LOADED
    _INVENTORY_PARSER_REGISTRY_LOADED = False


# Path to bundled MCP registry (parsers/ is a subdir of agent_bom/)
_REGISTRY_PATH = Path(__file__).parent.parent / "mcp_registry.json"


_registry_cache: Optional[dict] = None


def _load_registry() -> dict:
    """Load the bundled MCP server registry (cached)."""
    global _registry_cache
    if _registry_cache is None:
        try:
            _registry_cache = json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not load MCP registry from %s: %s — server recognition disabled", _REGISTRY_PATH, exc)
            _registry_cache = {}
    return _registry_cache


def _extract_version_from_args(args: list[str]) -> str | None:
    """Try to extract a pinned version from server command args.

    Detects patterns like @1.2.3, ==1.2.3, or version flags.
    """
    for arg in args:
        if arg.startswith("-"):
            continue
        # npm-style: @scope/package@1.2.3
        m = re.search(r"@(\d+\.\d+[\w.-]*)\s*$", arg)
        if m:
            return m.group(1)
        # pip-style: package==1.2.3
        m = re.search(r"==(\d+\.\d+[\w.-]*)$", arg)
        if m:
            return m.group(1)
    return None


def _registry_pattern_matches(pattern: object, candidate: object) -> bool:
    pat = str(pattern or "").strip().lower()
    value = str(candidate or "").strip().lower()
    if not pat or not value:
        return False
    if pat == value:
        return True
    return re.search(rf"(^|[\s/@:_-]){re.escape(pat)}($|[\s/@:_-])", value) is not None


def _registry_purl(ecosystem: str, package_name: str, version: str) -> str:
    if ecosystem.lower() == "npm":
        return _npm_purl(package_name, version)
    return f"pkg:{ecosystem}/{package_name}@{version}"


_CONTAINER_COMMANDS = {"docker", "podman"}
_CONTAINER_RUN_VALUE_FLAGS = {
    "-a",
    "--add-host",
    "--attach",
    "--cap-add",
    "--cap-drop",
    "--cidfile",
    "--cpus",
    "--dns",
    "--entrypoint",
    "-e",
    "--env",
    "--env-file",
    "--expose",
    "-h",
    "--hostname",
    "--ip",
    "--label",
    "--label-file",
    "-m",
    "--memory",
    "--mount",
    "--name",
    "--network",
    "--platform",
    "-p",
    "--publish",
    "--security-opt",
    "--user",
    "-u",
    "-v",
    "--volume",
    "-w",
    "--workdir",
}


def _split_container_image_ref(image_ref: str) -> tuple[str, str]:
    image = image_ref.strip()
    if "@sha256:" in image:
        name, digest = image.split("@", 1)
        return name, digest
    last_segment = image.rsplit("/", 1)[-1]
    if ":" in last_segment:
        name, version = image.rsplit(":", 1)
        return name, version
    return image, "latest"


def _docker_purl(name: str, version: str) -> str:
    return f"pkg:docker/{quote(name, safe='/')}@{quote(version, safe='')}"


def _docker_run_image_arg(args: list[str]) -> str | None:
    index = 0
    if index < len(args) and args[index] == "container":
        index += 1
    if index >= len(args) or args[index] != "run":
        return None
    index += 1

    while index < len(args):
        arg = args[index]
        if arg == "--":
            return args[index + 1] if index + 1 < len(args) else None
        if not arg.startswith("-"):
            return arg
        if "=" in arg:
            index += 1
            continue
        if arg in _CONTAINER_RUN_VALUE_FLAGS:
            index += 2
            continue
        index += 1
    return None


def detect_docker_image_package(server: MCPServer) -> list[Package]:
    """Extract the image reference from docker/podman MCP server commands."""
    surface = getattr(getattr(server, "surface", ""), "value", getattr(server, "surface", ""))
    if surface == "container-image":
        return []
    command = Path(server.command or "").name
    if command not in _CONTAINER_COMMANDS:
        return []
    image_ref = _docker_run_image_arg(server.args)
    if not image_ref:
        return []
    name, version = _split_container_image_ref(image_ref)
    return [
        Package(
            name=name,
            version=version,
            ecosystem="docker",
            purl=_docker_purl(name, version),
            is_direct=True,
            version_source="detected",
        )
    ]


def lookup_mcp_registry(server: MCPServer) -> list[Package]:
    """Look up an MCP server's packages using the bundled registry.

    Matches on:
    1. Exact npm package name in args (e.g. @modelcontextprotocol/server-filesystem)
    2. command_patterns substring match against server name or args

    Preserves the registry's latest_version in registry_version for drift
    comparison, and tries to detect the actual installed version from args.
    If no installed version is detectable, version is set to "latest" so the
    resolver can query npm/PyPI for the real current version.
    """
    registry = _load_registry()
    if not registry:
        return []

    candidates: list[str] = [server.name] + server.args

    for pkg_name, entry in registry.items():
        patterns = entry.get("command_patterns", [pkg_name])
        for candidate in candidates:
            for pattern in patterns:
                if _registry_pattern_matches(pattern, candidate) or _registry_pattern_matches(pkg_name, candidate):
                    ecosystem = entry.get("ecosystem", "npm")
                    registry_version = entry.get("latest_version", "latest")
                    risk_level = entry.get("risk_level")
                    verified = entry.get("verified", False)

                    # Try to detect actual installed version from args
                    detected_version = _extract_version_from_args(server.args)
                    if detected_version:
                        version = detected_version
                        version_source = "detected"
                    else:
                        # Use the bundled registry version when we have it so
                        # MCP package coverage does not depend on a live npm
                        # lookup succeeding under rate limits.
                        version = registry_version if registry_version not in ("", "latest", "unknown", "{{VERSION}}") else "latest"
                        version_source = "registry_fallback"

                    # Log warnings for unverified or high-risk servers
                    if not verified:
                        logger.info(
                            "Registry: %s is UNVERIFIED — review source before trusting",
                            entry["package"],
                        )
                    if risk_level == "high":
                        logger.info(
                            "Registry: %s has HIGH risk level — has privileged tool access",
                            entry["package"],
                        )

                    return [
                        Package(
                            name=entry["package"],
                            version=version,
                            ecosystem=ecosystem,
                            purl=_registry_purl(ecosystem, entry["package"], version),
                            is_direct=True,
                            resolved_from_registry=True,
                            registry_version=registry_version,
                            version_source=version_source,
                        )
                    ]
    return []


def get_registry_entry(server: MCPServer) -> dict | None:
    """Return the full registry entry for an MCP server, or None."""
    registry = _load_registry()
    if not registry:
        return None

    candidates: list[str] = [server.name] + server.args

    for pkg_name, entry in registry.items():
        patterns = entry.get("command_patterns", [pkg_name])
        for candidate in candidates:
            for pattern in patterns:
                if _registry_pattern_matches(pattern, candidate) or _registry_pattern_matches(pkg_name, candidate):
                    return entry
    return None


console = Console(stderr=True)
logger = logging.getLogger(__name__)


def find_server_directory(server: MCPServer) -> Optional[Path]:
    """Attempt to find the MCP server's source directory."""
    # Check working_dir first
    if server.working_dir and os.path.isdir(server.working_dir):
        return Path(server.working_dir)

    # Check args for paths
    for arg in server.args:
        if os.path.isdir(arg):
            return Path(arg)
        # Check if arg is a file, use its parent
        if os.path.isfile(arg):
            return Path(arg).parent

    # For npx/npm commands, check if there's a package reference
    if server.command in ("npx", "npm"):
        # npx packages are in node_modules or global cache
        for arg in server.args:
            if not arg.startswith("-"):
                # This is likely the package name
                return None  # Can't resolve npx packages to local dirs

    # For uvx/uv commands
    if server.command in ("uvx", "uv"):
        return None  # Virtual env packages

    # For direct python/node commands, check the script path
    if server.command in ("python", "python3", "node"):
        for arg in server.args:
            if not arg.startswith("-") and os.path.isfile(arg):
                return Path(arg).parent

    return None


def extract_packages(
    server: MCPServer,
    resolve_transitive: bool = False,
    max_depth: int = 3,
    smithery_token: str | None = None,
    mcp_registry: bool = False,
) -> list[Package]:
    """Extract all packages for an MCP server.

    Args:
        server: The MCP server to extract packages from
        resolve_transitive: If True, resolve transitive dependencies for npx/uvx packages
        max_depth: Maximum depth for transitive dependency resolution
        smithery_token: Optional Smithery API key for live registry fallback
        mcp_registry: If True, query the Official MCP Registry as a fallback
    """
    packages = []

    # Try direct command extraction first
    npx_packages = detect_npx_package(server)
    uvx_packages = detect_uvx_package(server)
    docker_packages = detect_docker_image_package(server)
    packages.extend(npx_packages)
    packages.extend(uvx_packages)
    packages.extend(docker_packages)

    # Try to find local directory and parse manifests
    server_dir = find_server_directory(server)
    if server_dir:
        packages.extend(parse_npm_packages(server_dir))
        packages.extend(parse_yarn_lock(server_dir))
        packages.extend(parse_pnpm_lock(server_dir))
        packages.extend(parse_bun_packages(server_dir))
        packages.extend(parse_pip_packages(server_dir))  # includes poetry.lock + uv.lock
        packages.extend(parse_pip_compile_inputs(server_dir))
        packages.extend(parse_conda_environment(server_dir))
        packages.extend(parse_conda_packages(server_dir))
        packages.extend(parse_go_packages(server_dir))
        packages.extend(parse_cargo_packages(server_dir))
        packages.extend(parse_maven_packages(server_dir))
        packages.extend(parse_gradle_packages(server_dir))
        packages.extend(parse_nuget_packages(server_dir))

    # If we only got npx/uvx packages (no local directory), resolve transitive deps
    if resolve_transitive and (npx_packages or uvx_packages) and not server_dir:
        console.print(f"  [cyan]→[/cyan] Resolving transitive dependencies for {server.name} (depth={max_depth})...")
        from agent_bom.transitive import resolve_transitive_dependencies_sync

        # Resolve transitive deps for npx/uvx packages only
        remote_packages = npx_packages + uvx_packages
        transitive_deps = resolve_transitive_dependencies_sync(remote_packages, max_depth)
        packages.extend(transitive_deps)

        if transitive_deps:
            console.print(f"  [green]✓[/green] Found {len(transitive_deps)} transitive dependencies")

    # Registry fallback: if we still have no packages, look up by server name/args
    if not packages and server.allows_registry_resolution:
        registry_packages = lookup_mcp_registry(server)
        if registry_packages:
            console.print(f"  [dim cyan]→ {server.name}: resolved from MCP registry ({registry_packages[0].name})[/dim cyan]")
            # Enrich server with permission profile from registry data
            entry = get_registry_entry(server)
            if entry:
                from agent_bom.permissions import build_permission_profile

                tool_names = entry.get("tools", [])
                cred_vars = entry.get("credential_env_vars", [])
                profile = build_permission_profile(
                    tools=tool_names,
                    credential_env_vars=cred_vars,
                    command=server.command,
                    args=server.args,
                )
                # Merge with discovery-time profile if present
                if server.permission_profile is not None:
                    profile.runs_as_root = profile.runs_as_root or server.permission_profile.runs_as_root
                    profile.shell_access = profile.shell_access or server.permission_profile.shell_access
                    profile.container_privileged = server.permission_profile.container_privileged
                    profile.capabilities = server.permission_profile.capabilities
                    profile.security_opt = server.permission_profile.security_opt
                server.permission_profile = profile
        packages.extend(registry_packages)

    # Official MCP Registry fallback: free API, no auth required
    if not packages and mcp_registry and server.allows_registry_resolution:
        try:
            from agent_bom.mcp_official_registry import official_registry_lookup_sync

            mcp_reg_packages = official_registry_lookup_sync(server)
            if mcp_reg_packages:
                console.print(f"  [dim blue]→ {server.name}: resolved from Official MCP Registry ({mcp_reg_packages[0].name})[/dim blue]")
            packages.extend(mcp_reg_packages)
        except Exception as exc:
            logger.debug("Official MCP Registry lookup failed for %s: %s", server.name, exc)

    # Smithery fallback: if local registry also missed, try Smithery API
    if not packages and smithery_token and server.allows_registry_resolution:
        try:
            from agent_bom.smithery import smithery_lookup_sync

            smithery_packages = smithery_lookup_sync(server, token=smithery_token)
            if smithery_packages:
                console.print(f"  [dim magenta]→ {server.name}: resolved from Smithery ({smithery_packages[0].name})[/dim magenta]")
            packages.extend(smithery_packages)
        except Exception as exc:
            logger.debug("Smithery lookup failed for %s: %s", server.name, exc)

    # Deduplicate
    seen = set()
    unique = []
    for pkg in packages:
        key = (pkg.name, pkg.version, pkg.ecosystem)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


# ── Project directory scanner ─────────────────────────────────────────────────

#: Package manifest file names that indicate a scannable directory.
_MANIFEST_FILES = frozenset(
    {
        "package.json",
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "requirements.txt",
        "requirements.in",
        "constraints.txt",
        "Pipfile.lock",
        "pyproject.toml",
        "poetry.lock",
        "uv.lock",
        "environment.yml",
        "environment.yaml",
        "conda-lock.yml",
        "go.mod",
        "go.sum",
        "Cargo.toml",
        "Cargo.lock",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gradle.lockfile",
        "packages.lock.json",
        "Gemfile",
        "Gemfile.lock",
        "composer.json",
        "composer.lock",
        "Package.resolved",
    }
)

#: Lockfile / resolved-dependency artifacts that should count as stronger
#: package-evidence than manifest-only declarations in project scans.
_LOCKFILE_FILES = frozenset(
    {
        "package-lock.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "bun.lock",
        "bun.lockb",
        "Pipfile.lock",
        "poetry.lock",
        "uv.lock",
        "conda-lock.yml",
        "go.sum",
        "Cargo.lock",
        "gradle.lockfile",
        "packages.lock.json",
        "Gemfile.lock",
        "composer.lock",
        "Package.resolved",
    }
)

#: Directories to skip during recursive project scan.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        ".env",
        "dist",
        "build",
        ".cache",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "target",  # Rust/Maven
        ".cargo",
        ".claude",  # Claude Code worktrees
        ".codex",  # Codex worktrees
    }
)


def _has_manifest(directory: Path) -> bool:
    """Return True if *directory* contains at least one package manifest."""
    return any((directory / name).exists() for name in _MANIFEST_FILES)


def _manifest_file_names(directory: Path) -> list[str]:
    """Return sorted manifest-like files present in *directory*."""
    return sorted(name for name in _MANIFEST_FILES if (directory / name).exists())


def summarize_project_inventory(
    root: Path,
    dir_map: dict[Path, list[Package]],
) -> dict[str, object]:
    """Summarize manifest/lockfile coverage for a project scan.

    This keeps lockfile-driven project scanning visible in CLI/JSON output so
    users can tell whether a project scan was backed by resolved lockfiles or
    only manifest declarations.
    """
    root = Path(root).resolve()
    directories: list[dict[str, object]] = []
    ecosystems: dict[str, int] = {}
    total_packages = 0
    total_direct = 0
    total_transitive = 0
    manifest_file_total = 0
    lockfile_total = 0
    lockfile_directories = 0
    declaration_only_directories = 0
    lockfile_backed_packages = 0
    declaration_only_packages = 0
    lockfile_backed_direct_packages = 0
    lockfile_backed_transitive_packages = 0
    declaration_only_direct_packages = 0
    declaration_only_transitive_packages = 0

    for directory, packages in sorted(dir_map.items(), key=lambda item: str(item[0])):
        manifest_files = _manifest_file_names(directory)
        lockfiles = [name for name in manifest_files if name in _LOCKFILE_FILES]
        manifests = [name for name in manifest_files if name not in _LOCKFILE_FILES]
        direct_count = sum(1 for pkg in packages if pkg.is_direct)
        transitive_count = len(packages) - direct_count
        advisory_evidence = "lockfile_backed" if lockfiles else "declaration_only"

        rel_path = "." if directory == root else str(directory.relative_to(root))
        eco_breakdown: dict[str, int] = {}
        for pkg in packages:
            eco_breakdown[pkg.ecosystem] = eco_breakdown.get(pkg.ecosystem, 0) + 1
            ecosystems[pkg.ecosystem] = ecosystems.get(pkg.ecosystem, 0) + 1

        directories.append(
            {
                "path": rel_path,
                "package_count": len(packages),
                "direct_packages": direct_count,
                "transitive_packages": transitive_count,
                "manifest_files": manifest_files,
                "lockfile_files": lockfiles,
                "declaration_files": manifests,
                "advisory_evidence": advisory_evidence,
                "ecosystems": eco_breakdown,
            }
        )
        total_packages += len(packages)
        total_direct += direct_count
        total_transitive += transitive_count
        manifest_file_total += len(manifest_files)
        lockfile_total += len(lockfiles)
        if lockfiles:
            lockfile_directories += 1
            lockfile_backed_packages += len(packages)
            lockfile_backed_direct_packages += direct_count
            lockfile_backed_transitive_packages += transitive_count
        else:
            declaration_only_directories += 1
            declaration_only_packages += len(packages)
            declaration_only_direct_packages += direct_count
            declaration_only_transitive_packages += transitive_count

    advisory_depth_pct = round(lockfile_backed_packages / total_packages * 100) if total_packages else 0

    return {
        "root": str(root),
        "manifest_directories": len(dir_map),
        "lockfile_directories": lockfile_directories,
        "declaration_only_directories": declaration_only_directories,
        "manifest_files": manifest_file_total,
        "lockfiles": lockfile_total,
        "declaration_only_files": manifest_file_total - lockfile_total,
        "package_count": total_packages,
        "direct_packages": total_direct,
        "transitive_packages": total_transitive,
        "lockfile_backed_packages": lockfile_backed_packages,
        "declaration_only_packages": declaration_only_packages,
        "lockfile_backed_direct_packages": lockfile_backed_direct_packages,
        "lockfile_backed_transitive_packages": lockfile_backed_transitive_packages,
        "declaration_only_direct_packages": declaration_only_direct_packages,
        "declaration_only_transitive_packages": declaration_only_transitive_packages,
        "advisory_depth_pct": advisory_depth_pct,
        "ecosystems": ecosystems,
        "directories": directories,
    }


def scan_project_directory(
    root: Path,
    max_depth: int = 5,
) -> dict[Path, list[Package]]:
    """Recursively walk *root* for package manifests and parse all packages.

    Returns a mapping of ``{directory: [Package, ...]}`` for each directory
    that contains at least one supported manifest file.  Directories in
    ``_SKIP_DIRS`` and hidden directories (starting with ``.``) beyond the
    root are silently skipped.

    Args:
        root: Project root directory to scan.
        max_depth: Maximum directory depth to descend (default 5).

    Returns:
        Dict mapping each manifest-bearing directory to its parsed packages.
        Empty dict if no manifests are found.
    """
    root = Path(root).resolve()
    results: dict[Path, list[Package]] = {}

    visited_real: set[str] = set()

    def _walk(directory: Path, depth: int) -> None:
        if depth > max_depth:
            return
        real = str(directory.resolve())
        if real in visited_real:
            return
        visited_real.add(real)

        if _has_manifest(directory):
            pkgs: list[Package] = []
            pkgs.extend(parse_npm_packages(directory))
            pkgs.extend(parse_yarn_lock(directory))
            pkgs.extend(parse_pnpm_lock(directory))
            pkgs.extend(parse_bun_packages(directory))
            pkgs.extend(parse_pip_packages(directory))
            pkgs.extend(parse_pip_compile_inputs(directory))
            pkgs.extend(parse_conda_environment(directory))
            pkgs.extend(parse_conda_packages(directory))
            pkgs.extend(parse_go_packages(directory))
            pkgs.extend(parse_cargo_packages(directory))
            pkgs.extend(parse_maven_packages(directory))
            pkgs.extend(parse_gradle_packages(directory))
            pkgs.extend(parse_nuget_packages(directory))
            pkgs.extend(parse_ruby_packages(directory))
            pkgs.extend(parse_php_packages(directory))
            pkgs.extend(parse_swift_packages(directory))

            # Deduplicate within this directory
            seen: set[tuple] = set()
            unique: list[Package] = []
            for pkg in pkgs:
                key = (pkg.name, pkg.version, pkg.ecosystem)
                if key not in seen:
                    seen.add(key)
                    unique.append(pkg)

            if unique:
                results[directory] = unique

        # Recurse into subdirectories
        try:
            subdirs = [
                d for d in directory.iterdir() if d.is_dir() and d.name not in _SKIP_DIRS and not (d.name.startswith(".") and depth > 0)
            ]
        except PermissionError:
            return

        for subdir in sorted(subdirs):
            _walk(subdir, depth + 1)

    _walk(root, 0)
    return results
