"""Parse package dependencies from MCP server directories."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Optional

from rich.console import Console

from agent_bom.models import MCPServer, Package

# Path to bundled MCP registry (parsers/ is a subdir of agent_bom/)
_REGISTRY_PATH = Path(__file__).parent.parent / "mcp_registry.json"
_registry_cache: Optional[dict] = None


def _load_registry() -> dict:
    """Load the bundled MCP server registry (cached)."""
    global _registry_cache
    if _registry_cache is None:
        try:
            _registry_cache = json.loads(_REGISTRY_PATH.read_text()).get("servers", {})
        except Exception:
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
                if pattern in candidate or candidate in pkg_name:
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
                        # Set to "latest" so resolver queries npm/PyPI
                        # for the actual current version
                        version = "latest"
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
                            purl=f"pkg:{ecosystem}/{entry['package']}@{version}",
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
                if pattern in candidate or candidate in pkg_name:
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


def parse_npm_packages(directory: Path) -> list[Package]:
    """Parse packages from package-lock.json or node_modules."""
    packages = []

    # Try package-lock.json first (most accurate)
    lock_file = directory / "package-lock.json"
    if lock_file.exists():
        try:
            lock_data = json.loads(lock_file.read_text())
            lock_packages = lock_data.get("packages", lock_data.get("dependencies", {}))

            # Get direct dependencies from package.json
            pkg_json = directory / "package.json"
            direct_deps = set()
            if pkg_json.exists():
                pkg_data = json.loads(pkg_json.read_text())
                direct_deps = set(pkg_data.get("dependencies", {}).keys())
                direct_deps.update(pkg_data.get("devDependencies", {}).keys())

            for name, info in lock_packages.items():
                if not isinstance(info, dict):
                    continue
                # Clean package name (remove node_modules/ prefix)
                clean_name = name.replace("node_modules/", "").lstrip("/")
                if not clean_name:
                    continue

                version = info.get("version", "unknown")
                packages.append(
                    Package(
                        name=clean_name,
                        version=version,
                        ecosystem="npm",
                        purl=f"pkg:npm/{clean_name}@{version}",
                        is_direct=clean_name in direct_deps,
                    )
                )
        except (json.JSONDecodeError, KeyError):
            pass

    # Fallback to package.json only
    elif (directory / "package.json").exists():
        try:
            pkg_data = json.loads((directory / "package.json").read_text())
            for dep_type in ("dependencies", "devDependencies"):
                for name, version_spec in pkg_data.get(dep_type, {}).items():
                    version = version_spec.lstrip("^~>=<")
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="npm",
                            purl=f"pkg:npm/{name}@{version}",
                            is_direct=True,
                        )
                    )
        except (json.JSONDecodeError, KeyError):
            pass

    return packages


def parse_pip_packages(directory: Path) -> list[Package]:
    """Parse packages from requirements.txt, Pipfile.lock, or pyproject.toml."""
    packages = []

    # Try requirements.txt
    req_file = directory / "requirements.txt"
    if req_file.exists():
        for line in req_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            # Parse name==version, name>=version, etc.
            match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", line)
            if match:
                name, _, version = match.groups()
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            else:
                # Just a name, no version
                name_match = re.match(r"^([a-zA-Z0-9_.-]+)", line)
                if name_match:
                    packages.append(
                        Package(
                            name=name_match.group(1),
                            version="unknown",
                            ecosystem="pypi",
                            is_direct=True,
                        )
                    )

    # Try Pipfile.lock
    pipfile_lock = directory / "Pipfile.lock"
    if pipfile_lock.exists() and not packages:
        try:
            lock_data = json.loads(pipfile_lock.read_text())
            for section in ("default", "develop"):
                for name, info in lock_data.get(section, {}).items():
                    if isinstance(info, dict):
                        version = info.get("version", "").lstrip("=")
                        packages.append(
                            Package(
                                name=name,
                                version=version or "unknown",
                                ecosystem="pypi",
                                purl=f"pkg:pypi/{name}@{version}" if version else None,
                                is_direct=section == "default",
                            )
                        )
        except (json.JSONDecodeError, KeyError):
            pass

    # Try pyproject.toml
    pyproject = directory / "pyproject.toml"
    if pyproject.exists() and not packages:
        try:
            import toml

            proj_data = toml.loads(pyproject.read_text())
            deps = proj_data.get("project", {}).get("dependencies", [])
            for dep in deps:
                match = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]+)\s*([a-zA-Z0-9_.*+-]+)", dep)
                if match:
                    name, _, version = match.groups()
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="pypi",
                            purl=f"pkg:pypi/{name}@{version}",
                            is_direct=True,
                        )
                    )
        except Exception as e:
            logger.debug(f"Failed to parse pyproject.toml at {pyproject}: {e}")

    return packages


def parse_go_packages(directory: Path) -> list[Package]:
    """Parse packages from go.sum."""
    packages = []
    go_sum = directory / "go.sum"

    if go_sum.exists():
        seen = set()
        for line in go_sum.read_text().splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                version = parts[1].split("/")[0].lstrip("v")
                key = (name, version)
                if key not in seen:
                    seen.add(key)
                    packages.append(
                        Package(
                            name=name,
                            version=version,
                            ecosystem="go",
                            purl=f"pkg:golang/{name}@{version}",
                            is_direct=True,
                        )
                    )

    return packages


def parse_cargo_packages(directory: Path) -> list[Package]:
    """Parse packages from Cargo.lock."""
    packages = []
    cargo_lock = directory / "Cargo.lock"

    if cargo_lock.exists():
        current_name = None
        current_version = None
        for line in cargo_lock.read_text().splitlines():
            line = line.strip()
            if line.startswith('name = "'):
                current_name = line.split('"')[1]
            elif line.startswith('version = "') and current_name:
                current_version = line.split('"')[1]
                packages.append(
                    Package(
                        name=current_name,
                        version=current_version,
                        ecosystem="cargo",
                        purl=f"pkg:cargo/{current_name}@{current_version}",
                        is_direct=True,
                    )
                )
                current_name = None
                current_version = None

    return packages


def detect_npx_package(server: MCPServer) -> list[Package]:
    """Extract package info from npx/npm commands."""
    packages = []
    if server.command not in ("npx", "npm"):
        return packages

    for arg in server.args:
        if arg.startswith("-"):
            continue
        # Parse @scope/package@version or package@version
        match = re.match(r"^(@?[a-zA-Z0-9_.-]+(?:/[a-zA-Z0-9_.-]+)?)(?:@(.+))?$", arg)
        if match:
            name = match.group(1)
            version = match.group(2) or "latest"
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    purl=f"pkg:npm/{name}@{version}",
                    is_direct=True,
                )
            )
            break  # First non-flag arg is the package

    return packages


def detect_uvx_package(server: MCPServer) -> list[Package]:
    """Extract package info from uvx/uv commands."""
    packages = []
    if server.command not in ("uvx", "uv"):
        return packages

    args = server.args
    for i, arg in enumerate(args):
        if arg in ("run", "tool") and i + 1 < len(args):
            pkg_arg = args[i + 1]
            match = re.match(r"^([a-zA-Z0-9_.-]+)(?:==(.+))?$", pkg_arg)
            if match:
                name = match.group(1)
                version = match.group(2) or "latest"
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            break
        elif not arg.startswith("-") and arg not in ("run", "tool"):
            match = re.match(r"^([a-zA-Z0-9_.-]+)(?:==(.+))?$", arg)
            if match:
                name = match.group(1)
                version = match.group(2) or "latest"
                packages.append(
                    Package(
                        name=name,
                        version=version,
                        ecosystem="pypi",
                        purl=f"pkg:pypi/{name}@{version}",
                        is_direct=True,
                    )
                )
            break

    return packages


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

    # Try npx/uvx command extraction first
    npx_packages = detect_npx_package(server)
    uvx_packages = detect_uvx_package(server)
    packages.extend(npx_packages)
    packages.extend(uvx_packages)

    # Try to find local directory and parse manifests
    server_dir = find_server_directory(server)
    if server_dir:
        packages.extend(parse_npm_packages(server_dir))
        packages.extend(parse_pip_packages(server_dir))
        packages.extend(parse_go_packages(server_dir))
        packages.extend(parse_cargo_packages(server_dir))

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
    if not packages:
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
    if not packages and mcp_registry:
        try:
            from agent_bom.mcp_official_registry import official_registry_lookup_sync

            mcp_reg_packages = official_registry_lookup_sync(server)
            if mcp_reg_packages:
                console.print(f"  [dim blue]→ {server.name}: resolved from Official MCP Registry ({mcp_reg_packages[0].name})[/dim blue]")
            packages.extend(mcp_reg_packages)
        except Exception as exc:
            logger.debug("Official MCP Registry lookup failed for %s: %s", server.name, exc)

    # Smithery fallback: if local registry also missed, try Smithery API
    if not packages and smithery_token:
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
