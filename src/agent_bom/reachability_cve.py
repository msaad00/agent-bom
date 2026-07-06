"""Join function-level symbol reachability to CVE affected-symbols.

Most SCA findings are package-level: "package X version Y is vulnerable,
and it appears in your dependency closure." That is noisy — the vast
majority of a lockfile is never exercised, and even when a vulnerable
package *is* imported, the specific function the advisory flags is often
never called from any agent entrypoint.

Two halves already exist in the codebase and this module is the join:

* **Symbol reach** — :func:`agent_bom.ast_python_analysis` builds a bounded
  tool-entrypoint -> imported-dependency-symbol call graph
  (:class:`agent_bom.ast_models.DependencySymbolReach`). It tells us which
  *symbols* of which *packages* are reachable from a live entrypoint.
* **Advisory symbols** — some OSV/GHSA advisories carry the affected
  *functions/symbols* under ``affected[].ecosystem_specific.imports`` (the
  OSV / Go-vulndb ``imports[].{path,symbols}`` shape). Most do not.

For a vulnerable package we extract the advisory's affected symbols (if
any) and intersect them with the project's reached symbol set. The result
is a three-state reachability signal on the finding:

* ``function_reachable`` — an affected symbol is actually reached from an
  entrypoint. Highest-confidence noise reduction: this CVE is exploitable
  through code you run.
* ``package_reachable`` — the package is imported / reached but either the
  advisory carries no symbol data or none of its symbols are reached. We
  *cannot prove* function reachability, so we never claim it.
* ``unreachable`` — the package is present in the dependency set but no
  entrypoint reaches it at all.

Honest scope: Python, npm, Go, Maven/Java, and Cargo/Rust symbol-level call
graphs are supported when import proof is available (``use`` / ``pom.xml`` /
``build.gradle``). Rust/Java regex parsers apply conservative guards and omit
heuristic rows so headless MCP consumers do not receive false ``function_reachable``
upgrades.

The module is read-only: no graph mutation, no network. It is safe to call
from the report layer, the graph/blast-radius surfacing, the API, or a
snapshot re-analysis pipeline.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from agent_bom.package_utils import normalize_package_ecosystem, normalize_package_name

if TYPE_CHECKING:
    from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
    from agent_bom.models import Vulnerability

# Three-state signal. Ordered most-specific (most reachable) first.
FUNCTION_REACHABLE = "function_reachable"
PACKAGE_REACHABLE = "package_reachable"
UNREACHABLE = "unreachable"

# Defensive bound: advisories occasionally carry pathological symbol lists.
# We never need to compare more than this many symbols to decide the signal.
_MAX_SYMBOLS = 512


def _normalize_pkg(name: str, ecosystem: str = "pypi") -> str:
    """Normalize a package name for cross-source matching."""
    eco = normalize_package_ecosystem(ecosystem or "pypi")
    return normalize_package_name(name or "", eco)


def _pkg_index_key(package: str, ecosystem: str) -> str:
    eco = normalize_package_ecosystem(ecosystem or "pypi")
    return f"{eco}:{_normalize_pkg(package, eco)}"


def _symbol_tokens(symbol: str) -> set[str]:
    """Expand one symbol string into comparable tokens.

    A reached symbol may be a dotted access like ``SandboxedEnvironment.from_string``
    while the advisory only names the type ``SandboxedEnvironment`` (or vice
    versa for a method-on-type advisory). We index both the full dotted form
    and its leading component so either side matches without leaking
    unrelated leaf names (we deliberately do *not* index the trailing
    ``.from_string`` leaf, which would over-match common method names).
    """
    sym = (symbol or "").strip()
    if not sym:
        return set()
    tokens = {sym}
    head = sym.split(".", 1)[0]
    if head:
        tokens.add(head)
    return tokens


@dataclass(frozen=True)
class SymbolReachIndex:
    """Per-package reached-symbol index built from AST symbol reach."""

    _symbols_by_key: dict[str, set[str]] = field(default_factory=dict)
    _paths_by_key: dict[str, tuple[str, ...]] = field(default_factory=dict)

    @classmethod
    def from_reaches(cls, reaches: Iterable["DependencySymbolReach"]) -> "SymbolReachIndex":
        symbols_by_key: dict[str, set[str]] = {}
        paths_by_key: dict[str, tuple[str, ...]] = {}
        for reach in reaches:
            if not reach.package:
                continue
            key = _pkg_index_key(reach.package, reach.ecosystem)
            bucket = symbols_by_key.setdefault(key, set())
            bucket |= _symbol_tokens(reach.symbol)
            # Keep the shortest (closest) call path as evidence per package.
            existing = paths_by_key.get(key)
            candidate = tuple(reach.call_path)
            if candidate and (existing is None or len(candidate) < len(existing)):
                paths_by_key[key] = candidate
        return cls(symbols_by_key, paths_by_key)

    @classmethod
    def from_ast_result(cls, result: "ASTAnalysisResult") -> "SymbolReachIndex":
        return cls.from_reaches(result.dependency_symbol_reach)

    def is_package_reached(self, package: str, *, ecosystem: str = "pypi") -> bool:
        """True when any symbol of ``package`` is reached from an entrypoint."""
        return _pkg_index_key(package, ecosystem) in self._symbols_by_key

    def symbols_for_package(self, package: str, *, ecosystem: str = "pypi") -> set[str]:
        return set(self._symbols_by_key.get(_pkg_index_key(package, ecosystem), set()))

    def call_path_for_package(self, package: str, *, ecosystem: str = "pypi") -> tuple[str, ...]:
        return self._paths_by_key.get(_pkg_index_key(package, ecosystem), ())

    def __bool__(self) -> bool:
        return bool(self._symbols_by_key)


@dataclass(frozen=True)
class AdvisoryIdentifiers:
    """CVE/CWE/CPE identifiers extracted from an advisory for reachability context."""

    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cpe_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class ReachabilitySignal:
    """The reachability verdict for one vulnerable package."""

    state: str  # FUNCTION_REACHABLE | PACKAGE_REACHABLE | UNREACHABLE
    package: str
    reason: str
    matched_symbols: tuple[str, ...] = ()
    advisory_symbols: tuple[str, ...] = ()
    call_path: tuple[str, ...] = ()
    advisory_identifiers: AdvisoryIdentifiers = field(default_factory=AdvisoryIdentifiers)

    @property
    def function_reachable(self) -> bool:
        return self.state == FUNCTION_REACHABLE


def _iter_affected_blocks(advisory: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    affected = advisory.get("affected")
    if not isinstance(affected, list):
        return
    for block in affected:
        if isinstance(block, Mapping):
            yield block


def _normalize_cve_id(value: str) -> str | None:
    token = (value or "").strip().upper()
    return token if token.startswith("CVE-") else None


def _normalize_cwe_id(value: str) -> str | None:
    token = (value or "").strip().upper()
    if not token:
        return None
    return token if token.startswith("CWE-") else f"CWE-{token}" if token.isdigit() else None


def _collect_cwe_tokens(raw: Any) -> set[str]:
    tokens: set[str] = set()
    if isinstance(raw, str):
        normalized = _normalize_cwe_id(raw)
        if normalized:
            tokens.add(normalized)
        return tokens
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            if isinstance(item, str):
                normalized = _normalize_cwe_id(item)
                if normalized:
                    tokens.add(normalized)
            elif isinstance(item, Mapping):
                ext_id = item.get("external_id") or item.get("cweId")
                if isinstance(ext_id, str):
                    normalized = _normalize_cwe_id(ext_id)
                    if normalized:
                        tokens.add(normalized)
    return tokens


def _symbols_from_database_specific(advisory: Mapping[str, Any]) -> set[str]:
    """GHSA/OSV symbol lists from ``database_specific`` and GHSA REST shapes."""
    tokens: set[str] = set()
    containers: list[Mapping[str, Any]] = []
    db = advisory.get("database_specific")
    if isinstance(db, Mapping):
        containers.append(db)
    containers.append(advisory)
    vulnerabilities = advisory.get("vulnerabilities")
    if isinstance(vulnerabilities, list):
        for entry in vulnerabilities:
            if isinstance(entry, Mapping):
                containers.append(entry)

    for container in containers:
        for key in ("vulnerable_functions", "vulnerableFunctions", "affected_functions"):
            raw = container.get(key)
            if not isinstance(raw, list):
                continue
            for item in raw:
                if isinstance(item, str):
                    tokens |= _symbol_tokens(item)
                    if len(tokens) >= _MAX_SYMBOLS:
                        return tokens
    return tokens


def advisory_affected_symbols_list(advisory: "Vulnerability | Mapping[str, Any] | None") -> list[str]:
    """Return sorted affected-symbol tokens ready for ``Vulnerability.affected_symbols``."""
    return sorted(extract_affected_symbols(advisory))


def extract_advisory_identifiers(advisory: "Vulnerability | Mapping[str, Any] | None") -> AdvisoryIdentifiers:
    """Extract CVE/CWE/CPE identifiers carried on an advisory."""
    cve_ids: set[str] = set()
    cwe_ids: set[str] = set()
    cpe_ids: set[str] = set()

    if advisory is None:
        return AdvisoryIdentifiers()

    primary_id = getattr(advisory, "id", None)
    if isinstance(primary_id, str):
        normalized = _normalize_cve_id(primary_id)
        if normalized:
            cve_ids.add(normalized)

    for alias in getattr(advisory, "aliases", None) or ():
        if isinstance(alias, str):
            normalized = _normalize_cve_id(alias)
            if normalized:
                cve_ids.add(normalized)

    cwe_ids |= _collect_cwe_tokens(getattr(advisory, "cwe_ids", None))

    if isinstance(advisory, Mapping):
        for alias in advisory.get("aliases", []) or []:
            if isinstance(alias, str):
                normalized = _normalize_cve_id(alias)
                if normalized:
                    cve_ids.add(normalized)
        db = advisory.get("database_specific")
        if isinstance(db, Mapping):
            cwe_ids |= _collect_cwe_tokens(db.get("cwe_ids") or db.get("cwes") or db.get("cwe"))
        for block in _iter_affected_blocks(advisory):
            pkg = block.get("package")
            if not isinstance(pkg, Mapping):
                continue
            for cpe_field in ("cpe", "cpes", "cpe23"):
                raw = pkg.get(cpe_field)
                if isinstance(raw, str) and raw.strip():
                    cpe_ids.add(raw.strip())
                elif isinstance(raw, list):
                    for item in raw:
                        if isinstance(item, str) and item.strip():
                            cpe_ids.add(item.strip())

    return AdvisoryIdentifiers(
        cve_ids=tuple(sorted(cve_ids)),
        cwe_ids=tuple(sorted(cwe_ids)),
        cpe_ids=tuple(sorted(cpe_ids)),
    )


def extract_affected_symbols(advisory: "Vulnerability | Mapping[str, Any] | None") -> set[str]:
    """Extract affected function/symbol names an advisory carries.

    Accepts either a raw OSV/GHSA advisory ``dict`` or a
    :class:`agent_bom.models.Vulnerability` (whose optional
    ``affected_symbols`` field is read directly). Returns the *normalized
    token set* ready for intersection with reached symbols — empty when the
    advisory carries no symbol data, which is the common case and the
    honest fallback to package-level reachability.

    OSV / Go-vulndb shape parsed::

        {"affected": [{"ecosystem_specific": {"imports": [
            {"path": "jinja2.sandbox", "symbols": ["SandboxedEnvironment"]}
        ]}}]}

    GHSA ``database_specific.vulnerable_functions`` is also parsed when present.
    """
    if advisory is None:
        return set()

    tokens: set[str] = set()

    # Vulnerability model: read the optional pre-extracted field.
    raw_field = getattr(advisory, "affected_symbols", None)
    if isinstance(raw_field, (list, tuple, set)):
        for sym in raw_field:
            if isinstance(sym, str):
                tokens |= _symbol_tokens(sym)
                if len(tokens) >= _MAX_SYMBOLS:
                    return tokens

    # Raw advisory mapping: parse ecosystem_specific.imports[].symbols.
    if isinstance(advisory, Mapping):
        tokens |= _symbols_from_database_specific(advisory)
        if len(tokens) >= _MAX_SYMBOLS:
            return tokens
        for block in _iter_affected_blocks(advisory):
            eco = block.get("ecosystem_specific")
            if not isinstance(eco, Mapping):
                continue
            imports = eco.get("imports")
            if not isinstance(imports, list):
                continue
            for imp in imports:
                if not isinstance(imp, Mapping):
                    continue
                symbols = imp.get("symbols")
                if not isinstance(symbols, list):
                    continue
                for sym in symbols:
                    if isinstance(sym, str):
                        tokens |= _symbol_tokens(sym)
                        if len(tokens) >= _MAX_SYMBOLS:
                            return tokens

    return tokens


def classify_reachability(
    *,
    package: str,
    advisory: "Vulnerability | Mapping[str, Any] | None",
    index: SymbolReachIndex,
    package_reachable: bool | None = None,
    ecosystem: str = "pypi",
) -> ReachabilitySignal:
    """Classify one vulnerable package into a three-state reachability signal.

    Parameters
    ----------
    package:
        The vulnerable package name (any case / separator style).
    advisory:
        The advisory carrying (or not) affected symbols. See
        :func:`extract_affected_symbols`.
    index:
        Reached-symbol index for the scanned project.
    package_reachable:
        Optional import / dependency-closure reach signal from the graph
        layer (``BlastRadius.graph_reachable``). When ``True`` it lets us
        report ``package_reachable`` for a package that is imported but
        whose symbols were not individually captured. ``None`` means the
        caller has no graph-reach evidence and we rely on the symbol index
        alone.
    ecosystem:
        Package ecosystem for index lookup (``pypi``, ``npm``, …).
    """
    eco = normalize_package_ecosystem(ecosystem or "pypi")
    advisory_symbols = extract_affected_symbols(advisory)
    advisory_ids = extract_advisory_identifiers(advisory)
    reached_symbols = index.symbols_for_package(package, ecosystem=eco)
    pkg_reached = index.is_package_reached(package, ecosystem=eco) or package_reachable is True
    call_path = index.call_path_for_package(package, ecosystem=eco)

    if advisory_symbols and reached_symbols:
        matched = sorted(advisory_symbols & reached_symbols)
        if matched:
            return ReachabilitySignal(
                state=FUNCTION_REACHABLE,
                package=package,
                reason="advisory affected symbol is reached from an entrypoint",
                matched_symbols=tuple(matched),
                advisory_symbols=tuple(sorted(advisory_symbols)),
                call_path=call_path,
                advisory_identifiers=advisory_ids,
            )

    if pkg_reached:
        if not advisory_symbols:
            reason = "package reached; advisory carries no symbol data"
        else:
            reason = "package reached but no affected symbol is reached"
        if advisory_ids.cwe_ids:
            reason = f"{reason}; CWE context: {', '.join(advisory_ids.cwe_ids)}"
        return ReachabilitySignal(
            state=PACKAGE_REACHABLE,
            package=package,
            reason=reason,
            advisory_symbols=tuple(sorted(advisory_symbols)),
            call_path=call_path,
            advisory_identifiers=advisory_ids,
        )

    return ReachabilitySignal(
        state=UNREACHABLE,
        package=package,
        reason="package present in dependencies but not reached from any entrypoint",
        advisory_symbols=tuple(sorted(advisory_symbols)),
        advisory_identifiers=advisory_ids,
    )


__all__ = [
    "FUNCTION_REACHABLE",
    "PACKAGE_REACHABLE",
    "UNREACHABLE",
    "AdvisoryIdentifiers",
    "SymbolReachIndex",
    "ReachabilitySignal",
    "advisory_affected_symbols_list",
    "extract_advisory_identifiers",
    "extract_affected_symbols",
    "classify_reachability",
]
