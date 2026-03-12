"""Go, Maven, Cargo, and uvx package parsers.

Parses go.mod/go.sum, pom.xml, Cargo.lock, and detects packages
from uvx/uv commands.
"""

from __future__ import annotations

import logging
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)

_GOPROXY_URL = "https://proxy.golang.org"
_CHECKSUM_DB_URL = "https://sum.golang.org"

# Versions that need resolution via the Go module proxy
_UNRESOLVED_VERSIONS = frozenset({"latest", "(devel)", "", "unknown"})


def _validate_https_url(url: str, param_name: str = "url") -> None:
    """Raise ValueError if *url* does not use HTTPS.

    All Go public API calls must use HTTPS — no plain-HTTP allowed.
    """
    if not url.startswith("https://"):
        raise ValueError(f"{param_name} must use https:// — got {url!r}. Only HTTPS URLs are accepted.")


def verify_go_checksums(
    go_sum: Path,
    modules: list[tuple[str, str]],
    checksum_db_url: str = _CHECKSUM_DB_URL,
    timeout: int = 10,
) -> dict[str, str]:
    """Verify go.sum hashes against the Go checksum database.

    For each module, fetches the expected hash from sum.golang.org and
    compares against go.sum.  Returns a dict of ``{module@version: status}``
    where status is one of:

    - ``"ok"``       — hash in go.sum matches the checksum database
    - ``"mismatch"`` — hash differs; the module may have been tampered with
      after being published (supply chain attack or corrupted download)
    - ``"missing"``  — module is not recorded in go.sum at all

    Uses the public Go checksum database (https://sum.golang.org) — no
    credentials are required.  Rate-limit friendly: only direct dependencies
    are checked, not every entry in go.sum.

    Security note:
        A ``"mismatch"`` status means the module content on disk differs from
        what the checksum database recorded at publish time.  This is a strong
        signal of either a supply chain compromise or a corrupted download and
        should be treated as a critical finding.

    Args:
        go_sum: Path to the ``go.sum`` file.
        modules: List of ``(module_path, version)`` tuples to verify.
            Versions must include the ``v`` prefix (e.g. ``"v1.2.3"``).
        checksum_db_url: Base URL of the Go checksum database.
            Must be HTTPS.  Defaults to ``https://sum.golang.org``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Dict mapping ``"module@version"`` to ``"ok"``, ``"mismatch"``, or
        ``"missing"``.  Entries where the network request failed are omitted
        rather than surfaced as errors — a warning is logged instead.
    """
    _validate_https_url(checksum_db_url, "checksum_db_url")

    # Build lookup table from go.sum: {module@version: h1:hash}
    # Skip /go.mod suffix lines — we verify the module zip hash only.
    sum_entries: dict[str, str] = {}
    if go_sum.exists():
        try:
            for line in go_sum.read_text(encoding="utf-8", errors="replace").splitlines():
                parts = line.strip().split()
                if len(parts) < 3:
                    continue
                mod, ver_raw, h1 = parts[0], parts[1], parts[2]
                if ver_raw.endswith("/go.mod"):
                    continue  # skip go.mod hash lines
                ver = ver_raw.split("/")[0]
                sum_entries[f"{mod}@{ver}"] = h1
        except OSError as exc:
            logger.warning("Could not read go.sum at %s: %s", go_sum, exc)
            return {}

    results: dict[str, str] = {}
    for mod, ver in modules:
        # Ensure version has the v prefix for the lookup key
        ver_key = ver if ver.startswith("v") else f"v{ver}"
        key = f"{mod}@{ver_key}"

        if key not in sum_entries:
            results[key] = "missing"
            continue

        local_hash = sum_entries[key]

        # Fetch expected hash from the checksum database
        lookup_url = f"{checksum_db_url}/lookup/{mod}@{ver_key}"
        try:
            req = urllib.request.Request(lookup_url)  # noqa: S310  # nosec B310 — HTTPS enforced above
            with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
                body = resp.read().decode("utf-8", errors="replace")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            logger.warning(
                "go.sum verification skipped for %s — checksum DB unreachable: %s",
                key,
                exc,
            )
            continue

        # The lookup response format (tile protocol):
        # Line 0: tree size
        # Line 1: hash (h1:BASE64=)
        # Line 2+: signed tree head
        db_hash: Optional[str] = None
        for line in body.splitlines():
            line = line.strip()
            if line.startswith("h1:"):
                db_hash = line
                break

        if db_hash is None:
            logger.warning("Unexpected checksum DB response format for %s", key)
            continue

        results[key] = "ok" if local_hash == db_hash else "mismatch"

    return results


def resolve_go_version(
    module: str,
    version: str,
    proxy_url: str = _GOPROXY_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Go module version using the Go module proxy.

    Queries ``https://proxy.golang.org/{module}/@v/list`` for the available
    version list and returns the latest stable release (no pre-release
    suffixes such as ``-rc``, ``-alpha``, ``-beta``, or ``-pre``).

    If *version* is already pinned (not ``"latest"``, ``"(devel)"``,
    ``""`` or ``"unknown"``), it is returned immediately without any
    network call.

    Never raises — any network error causes the original version string to
    be returned so that parsing can continue uninterrupted.

    Args:
        module: The Go module path (e.g. ``"github.com/gin-gonic/gin"``).
        version: Current version string.  Pass ``"latest"`` or ``""`` to
            trigger resolution.
        proxy_url: Base URL of the Go module proxy.  Must be HTTPS.
            Defaults to ``https://proxy.golang.org``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"v1.9.1"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(proxy_url, "proxy_url")

    encoded_module = urllib.parse.quote(module, safe="")
    list_url = f"{proxy_url}/{encoded_module}/@v/list"

    try:
        req = urllib.request.Request(list_url)  # noqa: S310  # nosec B310 — HTTPS enforced above
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original version on any failure
        logger.warning(
            "GOPROXY version resolution failed for %s — returning original version: %s",
            module,
            exc,
        )
        return version

    _prerelease_re = re.compile(r"-(rc|alpha|beta|pre)[\d.]*$", re.IGNORECASE)

    stable_versions: list[str] = []
    for raw in body.splitlines():
        v = raw.strip()
        if not v:
            continue
        if _prerelease_re.search(v):
            continue
        stable_versions.append(v)

    if not stable_versions:
        return version

    def _semver_key(v: str) -> tuple[int, ...]:
        """Return a numeric tuple for semver comparison."""
        # Strip leading 'v' and any build metadata
        cleaned = v.lstrip("v").split("+")[0]
        parts = cleaned.split(".")
        result = []
        for part in parts:
            # Strip any non-numeric suffix (e.g. "1" from "1rc1")
            numeric = re.match(r"(\d+)", part)
            result.append(int(numeric.group(1)) if numeric else 0)
        return tuple(result)

    stable_versions.sort(key=_semver_key)
    return stable_versions[-1]


def _parse_go_mod_requires(
    go_mod: Path,
) -> tuple[dict[str, str], dict[str, str], dict[str, tuple[str, str]]]:
    """Parse go.mod and return (direct, indirect, replace_map).

    Returns:
        direct: {module_path: version} for direct requires
        indirect: {module_path: version} for ``// indirect`` requires
        replace_map: {old_module: (new_module, new_version)} for replace directives
    """
    direct: dict[str, str] = {}
    indirect: dict[str, str] = {}
    replace_map: dict[str, tuple[str, str]] = {}

    if not go_mod.exists():
        return direct, indirect, replace_map

    try:
        content = go_mod.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return direct, indirect, replace_map

    block_re = re.compile(r"require\s*\(([^)]+)\)", re.DOTALL)
    single_re = re.compile(r"^require\s+(\S+)\s+(\S+)(.*)", re.MULTILINE)
    replace_re = re.compile(r"^replace\s+(\S+)(?:\s+\S+)?\s+=>\s+(\S+)\s+(\S+)", re.MULTILINE)

    # Block-style: require ( ... )
    for block in block_re.finditer(content):
        for line in block.group(1).splitlines():
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            is_indirect = "// indirect" in line
            clean = line.split("//")[0].strip()
            parts = clean.split()
            if len(parts) >= 2:
                mod, ver = parts[0], parts[1]
                (indirect if is_indirect else direct)[mod] = ver

    # Single-line: require module version [// indirect]
    for m in single_re.finditer(content):
        mod, ver, rest = m.group(1), m.group(2), m.group(3)
        (indirect if "indirect" in rest else direct)[mod] = ver

    # Replace directives: replace old => new version
    for m in replace_re.finditer(content):
        old_mod, new_mod, new_ver = m.group(1), m.group(2), m.group(3)
        replace_map[old_mod] = (new_mod, new_ver)

    return direct, indirect, replace_map


def parse_go_workspace(directory: Path) -> list[Package]:
    """Parse go.work for workspace module paths, then parse each module's go.mod.

    Supports Go 1.18+ multi-module workspaces.  Reads ``use`` directives from
    ``go.work`` and calls :func:`parse_go_packages` for each referenced module
    directory.  Deduplicates by ``(name, version)``; direct dependencies take
    priority over indirect when the same module appears in multiple modules.

    Args:
        directory: Directory containing the ``go.work`` file.

    Returns:
        Combined list of :class:`~agent_bom.models.Package` objects from all
        workspace modules.  Returns an empty list if ``go.work`` does not exist.
    """
    go_work = directory / "go.work"
    if not go_work.exists():
        return []

    try:
        content = go_work.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    # Parse "use ./module_path" directives (single-line and block forms)
    module_dirs: list[Path] = []

    # Block-style: use ( ... )
    block_re = re.compile(r"use\s*\(([^)]+)\)", re.DOTALL)
    for block in block_re.finditer(content):
        for raw in block.group(1).splitlines():
            raw = raw.strip()
            if raw and not raw.startswith("//"):
                module_dirs.append(directory / raw)

    # Single-line: use ./path
    single_re = re.compile(r"^use\s+(\S+)", re.MULTILINE)
    for m in single_re.finditer(content):
        # Avoid double-counting entries already captured by block form
        candidate = directory / m.group(1)
        if candidate not in module_dirs:
            module_dirs.append(candidate)

    if not module_dirs:
        return []

    # Parse each module and merge; prefer direct over indirect for duplicates
    seen_direct: dict[tuple[str, str], Package] = {}
    seen_indirect: dict[tuple[str, str], Package] = {}

    for mod_dir in module_dirs:
        for pkg in parse_go_packages(mod_dir):
            key = (pkg.name, pkg.version)
            if pkg.is_direct:
                seen_direct[key] = pkg
            else:
                seen_indirect.setdefault(key, pkg)

    # Merge: direct wins over indirect
    merged: dict[tuple[str, str], Package] = {**seen_indirect, **seen_direct}
    return list(merged.values())


def parse_go_packages(
    directory: Path,
    *,
    verify_checksums: bool = True,
    resolve_versions: bool = False,
) -> list[Package]:
    """Parse packages from go.mod and go.sum.

    If a ``go.work`` workspace file is present in *directory*, delegates to
    :func:`parse_go_workspace` to handle multi-module workspaces (Go 1.18+).

    Otherwise reads go.mod to correctly distinguish direct from indirect
    (transitive) dependencies and to apply ``replace`` directives.  Falls back
    to go.sum only when go.mod is absent, marking all packages as direct.

    Args:
        directory: Project root containing ``go.mod`` / ``go.sum``.
        verify_checksums: When ``True`` (default), compares go.sum hashes
            against the Go checksum database (``sum.golang.org``).  Any
            module whose hash does not match is flagged with
            ``is_malicious=True`` and an explanatory ``malicious_reason``.
            Requires outbound HTTPS access to ``sum.golang.org``.
        resolve_versions: When ``True``, unpinned versions (``"latest"``,
            ``"(devel)"``, ``""`` or ``"unknown"``) are resolved via the Go
            module proxy (``proxy.golang.org``).  Defaults to ``False`` to
            avoid network calls in pure parse mode — opt-in explicitly when
            version accuracy is required.
    """
    # Workspace mode takes priority
    go_work = directory / "go.work"
    if go_work.exists():
        return parse_go_workspace(directory)

    go_mod = directory / "go.mod"
    go_sum = directory / "go.sum"

    if not go_mod.exists() and not go_sum.exists():
        return []

    direct, indirect_mods, replace_map = _parse_go_mod_requires(go_mod)

    # Build combined module→(version, is_direct) map with replace applied
    all_mods: dict[str, tuple[str, bool]] = {}
    for source_map, is_direct in ((direct, True), (indirect_mods, False)):
        for mod, ver in source_map.items():
            if mod in replace_map:
                new_mod, new_ver = replace_map[mod]
                all_mods[new_mod] = (new_ver, is_direct)
            else:
                all_mods[mod] = (ver, is_direct)

    if all_mods:
        packages = []
        for mod, (ver, is_direct) in all_mods.items():
            # Optionally resolve unpinned versions via GOPROXY
            if resolve_versions and ver in _UNRESOLVED_VERSIONS:
                resolved = resolve_go_version(mod, ver)
                if resolved != ver:
                    ver = resolved
                    logger.debug("Resolved %s → %s via GOPROXY", mod, ver)

            clean_ver = ver[1:] if ver.startswith("v") else ver
            pkg = Package(
                name=mod,
                version=clean_ver,
                ecosystem="go",
                purl=f"pkg:golang/{mod}@{ver}",
                is_direct=is_direct,
            )
            if resolve_versions and pkg.version_source == "detected":
                # Mark the source so callers can distinguish
                pass  # version_source stays "detected"; proxy resolution is transparent
            packages.append(pkg)

        # Verify go.sum hashes for all direct modules
        if verify_checksums and go_sum.exists():
            modules_to_check = [(pkg.name, f"v{pkg.version}" if not pkg.version.startswith("v") else pkg.version) for pkg in packages]
            checksum_results = verify_go_checksums(go_sum, modules_to_check)
            pkg_by_key: dict[str, Package] = {}
            for pkg in packages:
                ver_key = f"v{pkg.version}" if not pkg.version.startswith("v") else pkg.version
                pkg_by_key[f"{pkg.name}@{ver_key}"] = pkg
            for key, status in checksum_results.items():
                if status == "mismatch" and key in pkg_by_key:
                    p = pkg_by_key[key]
                    p.is_malicious = True
                    p.malicious_reason = "go.sum hash mismatch: tampered module — hash on disk differs from sum.golang.org record"
                    logger.warning(
                        "go.sum hash mismatch for %s — possible supply chain tampering",
                        key,
                    )

        return packages

    # Fallback: go.sum only — all marked direct
    packages = []
    if go_sum.exists():
        seen: set[tuple[str, str]] = set()
        try:
            lines = go_sum.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines:
            parts = line.strip().split()
            if len(parts) >= 2:
                name = parts[0]
                raw_ver = parts[1].split("/")[0]  # strip /go.mod suffix
                clean_ver = raw_ver[1:] if raw_ver.startswith("v") else raw_ver
                mod_key = (name, clean_ver)
                if mod_key not in seen:
                    seen.add(mod_key)
                    packages.append(
                        Package(
                            name=name,
                            version=clean_ver,
                            ecosystem="go",
                            purl=f"pkg:golang/{name}@{raw_ver}",
                            is_direct=True,
                        )
                    )
    return packages


def _parse_pom_modules(root_dir: Path, depth: int = 0) -> list[Package]:
    """Recursively parse a Maven multi-module project.

    Reads the ``pom.xml`` at *root_dir*, collects its ``<dependency>``
    elements, then follows any ``<modules>/<module>`` child paths and recurses
    (up to 3 levels deep to guard against cycles).

    Args:
        root_dir: Directory containing a ``pom.xml``.
        depth: Current recursion depth (0 = root, max 3).

    Returns:
        Flat list of :class:`~agent_bom.models.Package` objects from this POM
        and all discovered sub-module POMs.
    """
    if depth > 3:
        return []

    import xml.etree.ElementTree as ET  # for ParseError type only

    from defusedxml.ElementTree import parse as safe_xml_parse  # B314

    pom = root_dir / "pom.xml"
    if not pom.exists():
        return []

    try:
        tree = safe_xml_parse(str(pom))
        xml_root = tree.getroot()
    except ET.ParseError as exc:
        logger.debug("Failed to parse pom.xml in %s: %s", root_dir, exc)
        return []

    # Namespace may or may not be present
    ns = ""
    if xml_root.tag.startswith("{"):
        ns = xml_root.tag.split("}")[0] + "}"

    def _find(el: "ET.Element", tag: str) -> "ET.Element | None":
        result = el.find(f"{ns}{tag}")
        return result if result is not None else el.find(tag)

    def _findall(el: "ET.Element", tag: str) -> "list[ET.Element]":
        results = el.findall(f"{ns}{tag}")
        return results if results else el.findall(tag)

    non_direct_scopes = {"test", "provided", "system"}
    packages: list[Package] = []

    for deps_el in _findall(xml_root, "dependencies"):
        for dep in _findall(deps_el, "dependency"):
            group_el = _find(dep, "groupId")
            artifact_el = _find(dep, "artifactId")
            version_el = _find(dep, "version")
            scope_el = _find(dep, "scope")

            if group_el is None or artifact_el is None:
                continue

            group_id = (group_el.text or "").strip()
            artifact_id = (artifact_el.text or "").strip()
            if not group_id or not artifact_id:
                continue

            # Skip unresolved property references and missing versions
            if version_el is None or not (version_el.text or "").strip():
                continue
            version = (version_el.text or "").strip()
            if version.startswith("${"):
                continue  # parent POM property — can't resolve statically

            scope = (scope_el.text or "compile").strip().lower() if scope_el is not None else "compile"
            is_direct = scope not in non_direct_scopes

            name = f"{group_id}:{artifact_id}"
            purl = f"pkg:maven/{group_id}/{artifact_id}@{version}"
            packages.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem="maven",
                    purl=purl,
                    is_direct=is_direct,
                )
            )

    # Recurse into sub-modules declared in <modules><module>...</module></modules>
    modules_el = _find(xml_root, "modules")
    if modules_el is not None:
        for module_el in _findall(modules_el, "module"):
            module_path = (module_el.text or "").strip()
            if not module_path:
                continue
            sub_dir = root_dir / module_path
            packages.extend(_parse_pom_modules(sub_dir, depth=depth + 1))

    return packages


def parse_maven_packages(directory: Path) -> list[Package]:
    """Parse packages from pom.xml (Maven/Java projects).

    Supports multi-module Maven projects: if the root ``pom.xml`` contains a
    ``<modules>`` section, each sub-module's ``pom.xml`` is recursively parsed
    (up to 3 levels deep).  The result is deduplicated by
    ``(groupId, artifactId)``; explicit versions are preferred over entries
    from nested modules with the same coordinates.

    Dependencies with scope ``test``, ``provided``, or ``system`` are included
    but marked ``is_direct=False`` since they are not deployed at runtime.
    Dependencies without a ``<version>`` element (version inherited via parent
    POM) are skipped — parent POM resolution requires network access.
    """
    pom = directory / "pom.xml"
    if not pom.exists():
        return []

    all_packages = _parse_pom_modules(directory, depth=0)

    # Deduplicate by (name, version) — first occurrence wins (root > submodule)
    seen: set[tuple[str, str]] = set()
    unique: list[Package] = []
    for pkg in all_packages:
        key = (pkg.name, pkg.version)
        if key not in seen:
            seen.add(key)
            unique.append(pkg)

    return unique


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


def detect_uvx_package(server: MCPServer) -> list[Package]:
    """Extract package info from uvx/uv commands."""
    packages: list[Package] = []
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
