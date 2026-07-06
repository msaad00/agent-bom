"""Conservative guards for regex-backed dependency symbol reach.

Headless agents and MCP posture tools consume ``dependency_symbol_reach``
evidence. Regex parsers (Rust/Java/Ruby) are intentionally lossy, so we only emit
rows that pass the same bar as Go: a proven import/use alias to an external
package plus a non-generic symbol token. Heuristic Maven coordinates and
unresolved MCP tool handlers are dropped rather than downgraded to
``function_reachable`` at join time.
"""

from __future__ import annotations

# Method names too generic to attribute to a third-party advisory symbol without
# a full type-aware resolver. Go still allows these when the import alias is
# proven; we apply the denylist only for regex parsers (Rust/Java).
_GENERIC_SYMBOL_DENYLIST: frozenset[str] = frozenset(
    {
        "build",
        "builder",
        "clone",
        "default",
        "execute",
        "into",
        "iter",
        "new",
        "run",
        "to_string",
        "url",
    }
)

# Rust std/internal crates are not Cargo.lock CVE targets for third-party join.
_RUST_INTRINSIC_CRATES: frozenset[str] = frozenset({"std", "core", "alloc", "proc_macro", "test", "self", "super", "crate"})


def is_actionable_dependency_symbol(symbol: str) -> bool:
    """Return True when a symbol token is specific enough to join advisories."""
    token = (symbol or "").strip()
    if not token or len(token) < 2:
        return False
    return token.lower() not in _GENERIC_SYMBOL_DENYLIST


def is_external_rust_crate(crate: str) -> bool:
    """Return True when a crate name is a third-party dependency candidate."""
    normalized = (crate or "").strip().lower()
    return bool(normalized) and normalized not in _RUST_INTRINSIC_CRATES


def is_verified_maven_coord(coord: str, maven_map: dict[str, str]) -> bool:
    """Return True when a Maven coord is declared in the project manifest map."""
    if not coord or not maven_map:
        return False
    return coord in set(maven_map.values())


def is_verified_nuget_package(package_id: str, nuget_map: dict[str, str]) -> bool:
    """Return True when a NuGet package ID is declared in the project manifest map."""
    if not package_id or not nuget_map:
        return False
    return package_id in set(nuget_map.values())


def is_verified_ruby_gem(gem_name: str, gem_map: dict[str, str]) -> bool:
    """Return True when a gem name is declared in the project manifest map."""
    if not gem_name or not gem_map:
        return False
    return gem_name in set(gem_map.values())


def is_verified_composer_package(package_name: str, package_map: dict[str, str]) -> bool:
    """Return True when a Composer package is declared in the project manifest map."""
    if not package_name or not package_map:
        return False
    return package_name in set(package_map.values())


def is_verified_swift_package(package_name: str, package_map: dict[str, str]) -> bool:
    """Return True when an SPM package identity is declared in Package.resolved."""
    if not package_name or not package_map:
        return False
    return package_name in set(package_map.values())


__all__ = [
    "is_actionable_dependency_symbol",
    "is_external_rust_crate",
    "is_verified_composer_package",
    "is_verified_maven_coord",
    "is_verified_nuget_package",
    "is_verified_ruby_gem",
    "is_verified_swift_package",
]
