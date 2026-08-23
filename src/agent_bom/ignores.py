"""Structured ignore/allowlist support for agent-bom.

Reads ``.agent-bom-ignore.yaml`` (or a path specified via ``--ignore-file``)
and marks matching blast-radius findings with the canonical suppression
overlay before output. Evidence remains available to JSON, SARIF, and VEX
consumers while active views and severity gates exclude approved suppressions.

Ignore file format::

    ignores:
      - id: CVE-2024-1234
        reason: "Not exploitable — no user input reaches affected path"
        expires: 2026-06-01

      - package: requests@<2.32.0
        reason: "Pinned, upgrade scheduled Q3"
        expires: 2026-09-01

      - package: lodash
        reason: "All lodash findings accepted — no internet-facing exposure"

      - type: credential-exposure
        path: "tests/**"
        reason: "Test fixtures with dummy credentials"

Fields
------
- ``id``      : CVE or OSV ID (exact match, case-insensitive).
- ``package`` : Package name, optionally with ``@<version-spec>``.
                A bare name matches all versions.  A ``@<spec>`` uses
                simple prefix comparison (``<``, ``<=``, ``==``).
- ``type``    : Finding type keyword (e.g. ``credential-exposure``).
- ``path``    : Glob matched against the config path of the discovering agent.
- ``expires`` : ISO date (``YYYY-MM-DD``).  Entry is ignored after this date.
- ``reason``  : Free-text (required for auditability).
"""

from __future__ import annotations

import fnmatch
import json
import logging
from datetime import date, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from agent_bom.models import BlastRadius

logger = logging.getLogger(__name__)

_DEFAULT_IGNORE_FILE = ".agent-bom-ignore.yaml"


def load_ignore_file(path: str | Path | None = None) -> list[dict[str, Any]]:
    """Load and parse an ignore file.  Returns empty list if file not found.

    Two formats are accepted:

    * **Structured YAML** — a mapping with an ``ignores:`` list (see the module
      docstring).  Supports per-entry reason/expiry/package/path metadata.
    * **Flat id list** — a newline-delimited list of CVE / GHSA / OSV ids, one
      per line, with ``#`` comments allowed (e.g. ``.image-scan-ignore``).
      Each id becomes ``{"id": <id>}`` and suppresses that advisory wherever it
      appears.  Used by CI image/filesystem gates that carry known-unfixable
      base-image CVEs.
    """
    target = Path(path) if path else Path(_DEFAULT_IGNORE_FILE)
    if not target.exists():
        return []

    try:
        text = target.read_text()
    except OSError as exc:
        raise ValueError(f"Could not read ignore file {target}: {exc}") from exc

    # Flat newline-delimited id lists are detected before YAML parsing because
    # multiple bare scalars on consecutive lines fold into a single YAML string
    # rather than the mapping the structured loader expects.
    if _looks_like_flat_id_list(text):
        return _parse_flat_id_list(text)

    try:
        import yaml  # type: ignore[import]
    except ImportError:
        try:
            import tomllib as _t  # noqa: F401
        except ImportError:
            pass
        # Fall back to a minimal YAML-subset parser (key: value lines only)
        return _parse_minimal_yaml(target)

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in ignore file {target}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"Ignore file {target} must be a YAML mapping with an 'ignores' list")
    entries = data.get("ignores", [])
    if not isinstance(entries, list):
        raise ValueError(f"Ignore file {target} field 'ignores' must be a list")
    return entries


def _looks_like_flat_id_list(text: str) -> bool:
    """Return True when *text* is a bare newline-delimited advisory-id list.

    A flat list has at least one meaningful line and no YAML mapping/sequence
    syntax (``key:`` mappings or ``-`` list items).  ``#`` comments and blank
    lines are ignored.
    """
    saw_id = False
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("-") or line.endswith(":") or ": " in line:
            return False
        saw_id = True
    return saw_id


def _parse_flat_id_list(text: str) -> list[dict[str, Any]]:
    """Parse legacy flat rules into the canonical structured entry format.

    The pre-structured ``.agent-bom-ignore`` syntax also allowed
    ``ecosystem:package`` and ``CVE:ecosystem:package``. Keep accepting those
    rules, but normalize them here so every consumer evaluates one format and
    one expiry gate.
    """
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        key = line.upper()
        if key in seen:
            continue
        seen.add(key)
        parts = line.split(":")
        if len(parts) == 2 and not parts[0].upper().startswith(("CVE-", "GHSA-")):
            entries.append(
                {
                    "ecosystem": parts[0],
                    "package": parts[1],
                    "reason": "Suppressed via legacy flat ignore rule",
                }
            )
        elif len(parts) == 3 and parts[0].upper().startswith(("CVE-", "GHSA-")):
            entries.append(
                {
                    "id": parts[0],
                    "ecosystem": parts[1],
                    "package": parts[2],
                    "reason": "Suppressed via legacy flat ignore rule",
                }
            )
        else:
            entries.append({"id": line, "reason": "Suppressed via flat ignore list"})
    return entries


def _parse_minimal_yaml(path: Path) -> list[dict[str, Any]]:
    """Fallback parser for simple ignore files when PyYAML is not installed."""
    try:
        text = path.read_text()
        # Try JSON as last resort
        if text.strip().startswith("{") or text.strip().startswith("["):
            data = json.loads(text)
            return data.get("ignores", data) if isinstance(data, dict) else data
    except OSError as exc:
        raise ValueError(f"Could not read ignore file {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in ignore file {path}: line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    raise ValueError("PyYAML is required for YAML ignore files: pip install pyyaml")


def _entry_is_expired(entry: dict[str, Any]) -> bool:
    """Return True if the entry has an expires field in the past."""
    expires = entry.get("expires")
    if not expires:
        return False
    try:
        exp_date = datetime.strptime(str(expires), "%Y-%m-%d").date()
        return exp_date < date.today()
    except ValueError:
        logger.warning("agent-bom-ignore: invalid expires date '%s' — treating as non-expired", expires)
        return False


def _matches_blast_radius(entry: dict[str, Any], br: "BlastRadius") -> bool:
    """Return True if this ignore entry covers the given blast-radius finding."""
    vuln = br.vulnerability
    pkg = br.package

    # CVE/OSV/GHSA ID match — checks the canonical id and any cross-source
    # aliases (e.g. a GHSA id suppresses its aliased CVE and vice versa).
    cve_id = entry.get("id")
    if cve_id:
        wanted = str(cve_id).upper()
        candidate_ids = {vuln.id.upper()}
        aliases = getattr(vuln, "aliases", None)
        if isinstance(aliases, (list, tuple, set)):
            candidate_ids.update(str(alias).upper() for alias in aliases)
        return wanted in candidate_ids

    # Package name / version match
    ecosystem = str(entry.get("ecosystem") or "").strip().lower()
    if ecosystem and ecosystem != str(pkg.ecosystem or "").strip().lower():
        return False

    pkg_spec = entry.get("package")
    if pkg_spec:
        pkg_spec = str(pkg_spec)
        if "@" in pkg_spec:
            name_part, ver_spec = pkg_spec.split("@", 1)
        else:
            name_part, ver_spec = pkg_spec, None

        from agent_bom.package_utils import normalize_package_name

        if normalize_package_name(pkg.name) != normalize_package_name(name_part):
            return False
        if ver_spec and not _version_matches(pkg.version or "", ver_spec):
            return False

    # Finding type match (e.g. "credential-exposure")
    finding_type = entry.get("type")
    if finding_type:
        if not _matches_finding_type(finding_type, br):
            return False

    # Path-scoped match
    path_glob = entry.get("path")
    if path_glob:
        agent_paths = [a.config_path or "" for a in br.affected_agents]
        if not any(fnmatch.fnmatch(p, path_glob) for p in agent_paths):
            return False

    # If we got here with at least one filter key set, it matched
    return bool(pkg_spec or finding_type or path_glob)


def _version_matches(version: str, spec: str) -> bool:
    """Simple version spec matching: <, <=, ==, >=, >."""
    spec = spec.strip()
    for op in ("<=", ">=", "==", "<", ">"):
        if spec.startswith(op):
            target = spec[len(op) :].strip()
            try:
                from packaging.version import Version

                v = Version(version)
                t = Version(target)
                if op == "<":
                    return v < t
                if op == "<=":
                    return v <= t
                if op == "==":
                    return v == t
                if op == ">":
                    return v > t
                if op == ">=":
                    return v >= t
            except Exception:
                # Fall back to string comparison
                if op == "==":
                    return version == target
    return version == spec


def _matches_finding_type(finding_type: str, br: "BlastRadius") -> bool:
    ft = finding_type.lower().replace("-", "_").replace(" ", "_")
    if ft == "credential_exposure":
        return bool(br.exposed_credentials)
    return False


def drop_unfixable(
    blast_radii: list["BlastRadius"],
) -> tuple[list["BlastRadius"], int]:
    """Drop blast-radius findings whose vulnerability has no available fix.

    Returns ``(kept, dropped_count)``.  A finding with no ``fixed_version``
    cannot be remediated by an upgrade; excluding it is the gate-level
    equivalent of an "ignore unfixed" policy.
    """
    kept: list["BlastRadius"] = []
    for br in blast_radii:
        fixed = getattr(br.vulnerability, "fixed_version", None)
        if isinstance(fixed, str) and fixed.strip():
            kept.append(br)
    return kept, len(blast_radii) - len(kept)


def apply_ignores(
    blast_radii: list["BlastRadius"],
    ignore_entries: list[dict[str, Any]],
) -> tuple[list["BlastRadius"], int]:
    """Apply ignore entries as auditable suppression overlays.

    Returns ``(original_list, suppressed_count)``. Evidence is never deleted:
    matching rows remain available to JSON/SARIF/VEX consumers with canonical
    suppression metadata, while actionability and risk gates see score zero.
    Expired entries are skipped with a warning.
    """
    if not ignore_entries:
        return blast_radii, 0

    active_entries: list[dict[str, Any]] = []
    for entry in ignore_entries:
        if _entry_is_expired(entry):
            cve = entry.get("id") or entry.get("package") or entry.get("type", "?")
            logger.warning("agent-bom-ignore: entry for '%s' expired on %s — re-surfacing", cve, entry["expires"])
        else:
            active_entries.append(entry)

    suppressed = 0
    for br in blast_radii:
        suppressed_by = next((e for e in active_entries if _matches_blast_radius(e, br)), None)
        if suppressed_by:
            from agent_bom.canonical_ids import canonical_id

            reason = suppressed_by.get("reason", "(no reason given)")
            logger.info(
                "agent-bom-ignore: suppressed %s in %s@%s — %s",
                br.vulnerability.id,
                br.package.name,
                br.package.version,
                reason,
            )
            br.suppressed = True
            br.suppression_id = canonical_id("ignore", suppressed_by)
            br.suppression_state = "accepted_risk"
            br.suppression_reason = str(reason)
            br.unsuppressed_risk_score = br.risk_score
            br.risk_score = 0.0
            br.transitive_risk_score = 0.0
            suppressed += 1

    return blast_radii, suppressed
