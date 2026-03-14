"""Go, Maven, Cargo, Gradle, conda, and uvx package parsers.

Parses go.mod/go.sum, pom.xml, Cargo.lock, build.gradle/build.gradle.kts/
libs.versions.toml/gradle.lockfile, environment.yml/conda-lock.yml,
and detects packages from uvx/uv commands.
"""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Optional

from agent_bom.models import MCPServer, Package

logger = logging.getLogger(__name__)

_GOPROXY_URL = "https://proxy.golang.org"
_CHECKSUM_DB_URL = "https://sum.golang.org"
_MAVEN_CENTRAL_URL = "https://search.maven.org"
_CRATES_IO_URL = "https://crates.io"

# Versions that need resolution via the Go module proxy
_UNRESOLVED_VERSIONS = frozenset({"latest", "(devel)", "", "unknown"})

# Versions that require Maven Central resolution
_MAVEN_UNRESOLVED_VERSIONS = frozenset({"RELEASE", "LATEST", "", "unknown"})

# Versions that require crates.io resolution
_CARGO_UNRESOLVED_VERSIONS = frozenset({"*", "", "latest", "unknown"})


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


def resolve_maven_version(
    group_id: str,
    artifact_id: str,
    version: str,
    *,
    maven_central_url: str = _MAVEN_CENTRAL_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Maven artifact version using the Maven Central Search API.

    Queries ``https://search.maven.org/solrsearch/select`` for the latest
    stable release of *group_id*:*artifact_id* and returns it.

    If *version* is already pinned (not ``"RELEASE"``, ``"LATEST"``, ``""``
    or ``"unknown"``), it is returned immediately without any network call.

    Skips pre-release versions with ``-SNAPSHOT``, ``-RC``, or ``-M``
    suffixes.  Never raises — any network or parse error causes the original
    version string to be returned so that parsing can continue uninterrupted.

    Args:
        group_id: Maven group ID (e.g. ``"org.springframework"``).
        artifact_id: Maven artifact ID (e.g. ``"spring-core"``).
        version: Current version string.  Pass ``"RELEASE"`` or ``"LATEST"``
            to trigger resolution.
        maven_central_url: Base URL of the Maven Central Search API.
            Must be HTTPS.  Defaults to ``https://search.maven.org``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"6.1.4"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _MAVEN_UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(maven_central_url, "maven_central_url")

    encoded_group = urllib.parse.quote(group_id, safe="")
    encoded_artifact = urllib.parse.quote(artifact_id, safe="")
    query = f"g:{encoded_group}+AND+a:{encoded_artifact}"
    api_url = f"{maven_central_url}/solrsearch/select?q={query}&rows=10&wt=json"

    _maven_prerelease_re = re.compile(r"-(SNAPSHOT|RC\d*|M\d+)$", re.IGNORECASE)

    try:
        req = urllib.request.Request(api_url)  # noqa: S310  # nosec B310 — HTTPS enforced above
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            raw_body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original on failure
        logger.warning(
            "Maven Central version resolution failed for %s:%s — returning original version: %s",
            group_id,
            artifact_id,
            exc,
        )
        return version

    try:
        data = json.loads(raw_body)
        docs = data.get("response", {}).get("docs", [])
        for doc in docs:
            candidate = (doc.get("v") or doc.get("latestVersion") or "").strip()
            if not candidate:
                continue
            if _maven_prerelease_re.search(candidate):
                continue
            return candidate
    except (ValueError, KeyError, AttributeError) as exc:
        logger.warning(
            "Failed to parse Maven Central response for %s:%s: %s",
            group_id,
            artifact_id,
            exc,
        )

    return version


def resolve_cargo_version(
    crate_name: str,
    version: str,
    *,
    crates_io_url: str = _CRATES_IO_URL,
    timeout: int = 5,
) -> str:
    """Resolve a Cargo crate version using the crates.io REST API.

    Queries ``https://crates.io/api/v1/crates/{crate_name}`` and returns
    the ``max_stable_version`` field, which is the latest non-pre-release
    version published for the crate.

    If *version* is already pinned (not ``"*"``, ``""``, ``"latest"`` or
    ``"unknown"``), it is returned immediately without any network call.

    Respects crates.io's rate-limit policy: sleeps 1 second when a network
    request is actually made.  Never raises — any error causes the original
    version string to be returned.

    Args:
        crate_name: Name of the Cargo crate (e.g. ``"serde"``).
        version: Current version string.  Pass ``"*"`` or ``""`` to trigger
            resolution.
        crates_io_url: Base URL of the crates.io API.  Must be HTTPS.
            Defaults to ``https://crates.io``.
        timeout: HTTP request timeout in seconds.

    Returns:
        Resolved version string (e.g. ``"1.0.196"``), or *version* unchanged
        if resolution fails or was not needed.
    """
    if version not in _CARGO_UNRESOLVED_VERSIONS:
        return version

    _validate_https_url(crates_io_url, "crates_io_url")

    encoded_name = urllib.parse.quote(crate_name, safe="")
    api_url = f"{crates_io_url}/api/v1/crates/{encoded_name}"
    from agent_bom import __version__

    user_agent = f"agent-bom/{__version__} (github.com/msaad00/agent-bom)"

    try:
        req = urllib.request.Request(api_url, headers={"User-Agent": user_agent})  # noqa: S310  # nosec B310 — HTTPS enforced above
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310  # nosec B310
            raw_body = resp.read().decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001 — never raise; return original on failure
        logger.warning(
            "crates.io version resolution failed for %s — returning original version: %s",
            crate_name,
            exc,
        )
        return version
    finally:
        # Respect crates.io rate-limit policy: 1 req/sec
        time.sleep(1)

    try:
        data = json.loads(raw_body)
        crate_data = data.get("crate", {})
        resolved = (crate_data.get("max_stable_version") or "").strip()
        if resolved:
            return resolved
    except (ValueError, KeyError, AttributeError) as exc:
        logger.warning(
            "Failed to parse crates.io response for %s: %s",
            crate_name,
            exc,
        )

    return version


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


def parse_maven_packages(directory: Path, *, resolve_versions: bool = False) -> list[Package]:
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

    Args:
        directory: Project directory containing ``pom.xml``.
        resolve_versions: When ``True``, packages with unresolved versions
            (``"RELEASE"``, ``"LATEST"``, ``""`` or ``"unknown"``) are queried
            against the Maven Central Search API to obtain their latest stable
            version.  Default ``False`` — no network calls.
    """
    pom = directory / "pom.xml"
    if not pom.exists():
        return []

    all_packages = _parse_pom_modules(directory, depth=0)

    # Deduplicate by (name, version) — first occurrence wins (root > submodule)
    maven_seen: set[tuple[str, str]] = set()
    unique: list[Package] = []
    for pkg in all_packages:
        maven_key = (pkg.name, pkg.version)
        if maven_key not in maven_seen:
            maven_seen.add(maven_key)
            unique.append(pkg)

    if resolve_versions:
        for pkg in unique:
            if pkg.version in _MAVEN_UNRESOLVED_VERSIONS and ":" in pkg.name:
                maven_group, maven_artifact = pkg.name.split(":", 1)
                resolved_ver = resolve_maven_version(maven_group, maven_artifact, pkg.version)
                if resolved_ver != pkg.version:
                    pkg.version = resolved_ver
                    pkg.purl = f"pkg:maven/{maven_group}/{maven_artifact}@{resolved_ver}"
                    pkg.version_source = "registry_fallback"

    return unique


def parse_cargo_packages(directory: Path, *, resolve_versions: bool = False) -> list[Package]:
    """Parse packages from Cargo.lock.

    Args:
        directory: Project directory containing ``Cargo.lock``.
        resolve_versions: When ``True``, packages with unresolved versions
            (``"*"``, ``""``, ``"latest"`` or ``"unknown"``) are queried
            against the crates.io REST API to obtain their latest stable
            version.  Adds a 1-second sleep between requests to respect
            crates.io rate limits.  Default ``False`` — no network calls.
    """
    cargo_packages: list[Package] = []
    cargo_lock = directory / "Cargo.lock"

    if cargo_lock.exists():
        current_name: Optional[str] = None
        current_version: Optional[str] = None
        for raw_line in cargo_lock.read_text().splitlines():
            stripped_line = raw_line.strip()
            if stripped_line.startswith('name = "'):
                current_name = stripped_line.split('"')[1]
            elif stripped_line.startswith('version = "') and current_name:
                current_version = stripped_line.split('"')[1]
                cargo_packages.append(
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

    if resolve_versions:
        for pkg in cargo_packages:
            if pkg.version in _CARGO_UNRESOLVED_VERSIONS:
                cargo_resolved = resolve_cargo_version(pkg.name, pkg.version)
                if cargo_resolved != pkg.version:
                    pkg.version = cargo_resolved
                    pkg.purl = f"pkg:cargo/{pkg.name}@{cargo_resolved}"
                    pkg.version_source = "registry_fallback"

    return cargo_packages


def parse_gradle_packages(directory: Path) -> list[Package]:
    """Parse packages from Gradle build files.

    Supports four file formats, checked in priority order:

    1. ``gradle/libs.versions.toml`` — Gradle 7+ version catalog (most accurate,
       resolves ``version.ref`` aliases).
    2. ``gradle.lockfile`` — resolved dependency lock file (exact versions,
       used when present alongside build scripts).
    3. ``build.gradle.kts`` — Kotlin DSL (double-quoted strings).
    4. ``build.gradle`` — Groovy DSL (single- or double-quoted strings).

    When a ``gradle.lockfile`` is found it supersedes any packages collected
    from the DSL build scripts because it contains resolved, exact versions.

    All dependencies use ``ecosystem="maven"`` because Gradle resolves
    packages through Maven Central / Maven repositories.  PURL format is
    ``pkg:maven/{groupId}/{artifactId}@{version}``.

    ``testImplementation`` and ``testRuntimeOnly`` configurations are marked
    ``is_direct=False``; all other configurations are ``is_direct=True``.

    Args:
        directory: Project directory to search for Gradle build files.

    Returns:
        List of :class:`~agent_bom.models.Package` objects.  Empty list when
        no Gradle files are found.
    """
    _test_configs = frozenset({"testimplementation", "testruntimeonly", "testcompileonly"})

    def _make_package(group_id: str, artifact_id: str, version: str, config: str = "") -> Package:
        name = f"{group_id}:{artifact_id}"
        is_direct = config.lower() not in _test_configs
        return Package(
            name=name,
            version=version,
            ecosystem="maven",
            purl=f"pkg:maven/{group_id}/{artifact_id}@{version}",
            is_direct=is_direct,
        )

    # ── 1. gradle/libs.versions.toml ─────────────────────────────────────────
    def _parse_version_catalog(path: Path) -> list[Package]:
        if not path.exists():
            return []
        packages: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        # Parse [versions] section — simple key = "value" pairs
        versions: dict[str, str] = {}
        in_versions = False
        in_libraries = False
        library_lines: list[str] = []

        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("["):
                in_versions = stripped.startswith("[versions]")
                in_libraries = stripped.startswith("[libraries]")
                continue
            if in_versions and "=" in stripped and not stripped.startswith("#"):
                k, _, v = stripped.partition("=")
                versions[k.strip()] = v.strip().strip('"').strip("'")
            if in_libraries and stripped and not stripped.startswith("#"):
                library_lines.append(stripped)

        # Parse library entries in [libraries]
        # Formats:
        #   alias = { module = "group:artifact", version.ref = "alias" }
        #   alias = { group = "g", name = "a", version.ref = "alias" }
        #   alias = { module = "group:artifact", version = "1.0" }
        for line in library_lines:
            if "=" not in line:
                continue
            _, _, rest = line.partition("=")
            rest = rest.strip()

            # Extract module or group+name
            module_m = re.search(r'module\s*=\s*["\']([^"\']+)["\']', rest)
            group_m = re.search(r'group\s*=\s*["\']([^"\']+)["\']', rest)
            name_m = re.search(r'\bname\s*=\s*["\']([^"\']+)["\']', rest)

            if module_m:
                parts = module_m.group(1).split(":")
                if len(parts) != 2:
                    continue
                group_id, artifact_id = parts[0].strip(), parts[1].strip()
            elif group_m and name_m:
                group_id = group_m.group(1).strip()
                artifact_id = name_m.group(1).strip()
            else:
                continue

            if not group_id or not artifact_id:
                continue

            # Resolve version
            version_ref_m = re.search(r'version\.ref\s*=\s*["\']([^"\']+)["\']', rest)
            version_lit_m = re.search(r'\bversion\s*=\s*["\']([^"\']+)["\']', rest)

            if version_ref_m:
                ref = version_ref_m.group(1).strip()
                version = versions.get(ref, "")
            elif version_lit_m:
                version = version_lit_m.group(1).strip()
            else:
                version = ""

            if not version:
                continue

            packages.append(_make_package(group_id, artifact_id, version))

        return packages

    # ── 2. gradle.lockfile ────────────────────────────────────────────────────
    def _parse_lockfile(path: Path) -> list[Package]:
        if not path.exists():
            return []
        packages: list[Package] = []
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("empty="):
                continue
            # Format: groupId:artifactId:version=configurations
            dep_part = line.split("=")[0].strip()
            parts = dep_part.split(":")
            if len(parts) >= 3:
                group_id, artifact_id, version = parts[0], parts[1], parts[2]
                if group_id and artifact_id and version:
                    packages.append(_make_package(group_id, artifact_id, version))
        return packages

    # ── 3 & 4. build.gradle / build.gradle.kts ───────────────────────────────
    def _parse_build_gradle(path: Path) -> list[Package]:
        if not path.exists():
            return []
        packages: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []

        # Match Kotlin DSL: configName("group:artifact:version")
        # and Groovy DSL:   configName 'group:artifact:version'
        #                   configName "group:artifact:version"
        _config_pat = (
            r"implementation|api|runtimeOnly|compileOnly|testImplementation|"
            r"testRuntimeOnly|testCompileOnly|annotationProcessor|kapt|"
            r"androidTestImplementation|debugImplementation|releaseImplementation"
        )
        _coord_pat = r"([\w][\w.\-]*):([\w][\w.\-]*):([\w][\w.\-]*)"
        # Kotlin DSL: configName("g:a:v") or configName( "g:a:v" )
        kotlin_re = re.compile(
            r"\b(" + _config_pat + r')\s*\(\s*["\']' + _coord_pat + r'["\']',
            re.IGNORECASE,
        )
        # Groovy DSL: configName 'g:a:v' or configName "g:a:v"
        groovy_re = re.compile(
            r"\b(" + _config_pat + r')\s+["\']' + _coord_pat + r'["\']',
            re.IGNORECASE,
        )
        seen_coords: set[tuple[str, str, str]] = set()
        for pattern in (kotlin_re, groovy_re):
            for m in pattern.finditer(content):
                config = m.group(1)
                group_id = m.group(2)
                artifact_id = m.group(3)
                version = m.group(4)
                coord = (group_id, artifact_id, version)
                if group_id and artifact_id and version and coord not in seen_coords:
                    seen_coords.add(coord)
                    packages.append(_make_package(group_id, artifact_id, version, config))
        return packages

    # ── Dispatch ──────────────────────────────────────────────────────────────
    catalog_path = directory / "gradle" / "libs.versions.toml"
    lockfile_path = directory / "gradle.lockfile"
    kts_path = directory / "build.gradle.kts"
    groovy_path = directory / "build.gradle"

    catalog_pkgs = _parse_version_catalog(catalog_path)
    lockfile_pkgs = _parse_lockfile(lockfile_path)
    kts_pkgs = _parse_build_gradle(kts_path)
    groovy_pkgs = _parse_build_gradle(groovy_path)

    # Merge: lockfile supersedes DSL scripts (more accurate resolved versions)
    # Catalog is supplemental (may declare deps not in lockfile for non-locked configs)
    if lockfile_pkgs:
        # Use lockfile as canonical; augment with catalog extras
        seen: set[tuple[str, str]] = {(p.name, p.version) for p in lockfile_pkgs}
        merged = list(lockfile_pkgs)
        for p in catalog_pkgs:
            if (p.name, p.version) not in seen:
                seen.add((p.name, p.version))
                merged.append(p)
        return merged

    # No lockfile: combine DSL + catalog, deduplicate
    all_pkgs = kts_pkgs + groovy_pkgs + catalog_pkgs
    seen_names: set[str] = set()
    unique: list[Package] = []
    for p in all_pkgs:
        if p.name not in seen_names:
            seen_names.add(p.name)
            unique.append(p)
    return unique


def parse_conda_packages(directory: Path) -> list[Package]:
    """Parse packages from conda environment files and lock files.

    Supports three file formats:

    * ``environment.yml`` / ``environment.yaml`` — conda environment
      specification.  Conda packages (``name=version``) are tagged
      ``ecosystem="conda"``; pip sub-dependencies (under the ``pip:`` key)
      are tagged ``ecosystem="pypi"``.  Channel prefixes such as
      ``pytorch::pytorch=2.1.0`` are stripped.
    * ``conda-lock.yml`` — platform-resolved lock file generated by
      ``conda-lock``.  Packages are deduplicated across platforms; the
      ``manager`` field determines ecosystem (``conda`` or ``pip``).

    Version specifiers:

    * ``=1.24.0`` → exact version ``1.24.0``
    * ``>=1.24.0`` → stored as-is (``>=1.24.0``)
    * No version → version stored as empty string ``""``

    Args:
        directory: Project directory to search for conda manifests.

    Returns:
        List of :class:`~agent_bom.models.Package` objects.  Empty list when
        no conda files are found.
    """
    packages: list[Package] = []

    # ── Helper: parse environment.yml / environment.yaml ─────────────────────
    def _parse_env_file(path: Path) -> list[Package]:
        pkgs: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return pkgs

        # Try YAML first; fall back to line-by-line
        data: dict | None = None
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(content) or {}
        except Exception:
            data = None

        if data is not None:
            for dep in data.get("dependencies", []):
                if isinstance(dep, str):
                    # Strip channel prefix: "channel::name=version" → "name=version"
                    if "::" in dep:
                        dep = dep.split("::", 1)[1]
                    # Parse "name=version" or "name=version=build"
                    parts = dep.split("=", 1)
                    pkg_name = parts[0].strip()
                    pkg_version = parts[1].strip() if len(parts) >= 2 else ""
                    if pkg_name:
                        pkgs.append(
                            Package(
                                name=pkg_name,
                                version=pkg_version,
                                ecosystem="conda",
                                purl=f"pkg:conda/{pkg_name}@{pkg_version}" if pkg_version else None,
                                is_direct=True,
                            )
                        )
                elif isinstance(dep, dict) and "pip" in dep:
                    for pip_dep in dep.get("pip", []):
                        if not isinstance(pip_dep, str):
                            continue
                        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]{1,2})\s*([a-zA-Z0-9_.*+!-]+)", pip_dep)
                        if m:
                            pip_name = m.group(1)
                            pip_op = m.group(2)
                            pip_ver = m.group(3)
                            # Normalise double-equals to bare version for ==, keep others as specifier
                            version_str = pip_ver if pip_op == "==" else f"{pip_op}{pip_ver}"
                            pkgs.append(
                                Package(
                                    name=pip_name,
                                    version=version_str,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{pip_name}@{version_str}",
                                    is_direct=True,
                                )
                            )
        else:
            # Fallback: line-by-line (no yaml library)
            in_deps = False
            in_pip = False
            for line in content.splitlines():
                stripped = line.strip()
                if stripped.startswith("dependencies:"):
                    in_deps = True
                    in_pip = False
                    continue
                if in_deps:
                    if stripped.startswith("- pip:"):
                        in_pip = True
                        continue
                    if stripped.startswith("-") and not stripped.startswith("- pip"):
                        in_pip = False
                        dep_raw = stripped.lstrip("- ").strip()
                        if "::" in dep_raw:
                            dep_raw = dep_raw.split("::", 1)[1]
                        parts = dep_raw.split("=", 1)
                        pkg_name = parts[0].strip()
                        pkg_version = parts[1].strip() if len(parts) >= 2 else ""
                        if pkg_name:
                            pkgs.append(
                                Package(
                                    name=pkg_name,
                                    version=pkg_version,
                                    ecosystem="conda",
                                    purl=f"pkg:conda/{pkg_name}@{pkg_version}" if pkg_version else None,
                                    is_direct=True,
                                )
                            )
                    elif in_pip and stripped.startswith("-"):
                        pip_dep = stripped.lstrip("- ").strip()
                        m = re.match(r"^([a-zA-Z0-9_.-]+)\s*([=<>!~]{1,2})\s*([a-zA-Z0-9_.*+!-]+)", pip_dep)
                        if m:
                            pip_name = m.group(1)
                            pip_op = m.group(2)
                            pip_ver = m.group(3)
                            version_str = pip_ver if pip_op == "==" else f"{pip_op}{pip_ver}"
                            pkgs.append(
                                Package(
                                    name=pip_name,
                                    version=version_str,
                                    ecosystem="pypi",
                                    purl=f"pkg:pypi/{pip_name}@{version_str}",
                                    is_direct=True,
                                )
                            )
        return pkgs

    # ── Helper: parse conda-lock.yml ─────────────────────────────────────────
    def _parse_lock_file(path: Path) -> list[Package]:
        pkgs: list[Package] = []
        try:
            content = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return pkgs

        data: dict | None = None
        try:
            import yaml  # type: ignore[import-untyped]

            data = yaml.safe_load(content) or {}
        except Exception:
            data = None

        if data is None:
            return pkgs

        seen: set[tuple[str, str, str]] = set()
        for entry in data.get("package", []):
            name = (entry.get("name") or "").strip()
            version = str(entry.get("version") or "").strip()
            manager = (entry.get("manager") or "conda").strip().lower()
            if not name or not version:
                continue
            key = (name, version, manager)
            if key in seen:
                continue
            seen.add(key)
            ecosystem = "pypi" if manager == "pip" else "conda"
            pkgs.append(
                Package(
                    name=name,
                    version=version,
                    ecosystem=ecosystem,
                    purl=f"pkg:{ecosystem}/{name}@{version}",
                    is_direct=True,
                )
            )
        return pkgs

    # ── Dispatch ──────────────────────────────────────────────────────────────
    conda_lock = directory / "conda-lock.yml"
    if conda_lock.exists():
        packages.extend(_parse_lock_file(conda_lock))

    for env_name in ("environment.yml", "environment.yaml"):
        env_path = directory / env_name
        if env_path.exists():
            packages.extend(_parse_env_file(env_path))
            break

    # Deduplicate by (name, version, ecosystem)
    seen_keys: set[tuple[str, str, str]] = set()
    unique: list[Package] = []
    for p in packages:
        key = (p.name, p.version, p.ecosystem)
        if key not in seen_keys:
            seen_keys.add(key)
            unique.append(p)
    return unique


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
