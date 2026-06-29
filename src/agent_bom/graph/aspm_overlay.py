"""ASPM (Application Security Posture Management) correlation overlay.

agent-bom already produces SCA, secrets, IaC, container, CI/CD, SBOM, and
AI-BOM findings — but they live next to one another, not *around an application*.
This overlay closes that gap by organising the AppSec signals already in the
graph around the **application** they belong to. It is a pure correlation layer
over the existing findings + graph; it adds **no scanners**.

For each unified finding the report already carries (``report_json["findings"]``,
one ``Finding.to_dict()`` per issue), the overlay:

- **Derives an application identity** per service / repo / manifest-root from the
  finding's source path (``asset.location``) or asset name — each manifest
  directory / repo root becomes one ``APPLICATION`` node, with a best-effort
  owner pulled from the report's CODEOWNERS / manifest metadata when present.
- **Aggregates** every finding (SCA / secrets / IaC / container / CI-CD / AI-BOM)
  to its application via a ``BELONGS_TO`` edge from the finding's existing graph
  node, and computes a deterministic per-app risk roll-up (counts by severity +
  a per-app risk score).
- **Deduplicates cross-finding**: within an application, findings that name the
  same CVE / rule on the same component across multiple sources are merged so
  they are counted once, while every reporting source is kept as provenance.
- **Flags reachability**: where the graph already carries reachability /
  attack-path signal for a finding's component, the finding is marked
  ``reachable`` vs ``not_reachable``; ``unknown`` otherwise. No new reachability
  engine is built — only existing attack-path data is consulted.

The overlay is a pure in-place graph mutation: **idempotent** (applying twice
yields identical nodes / edges / attributes), **deterministic** (every iteration
is sorted; dedup is keyed on a stable ``(app, component, rule/cve)`` tuple), and
a complete **no-op** when the report carries no findings / no derivable apps —
the graph stays byte-identical to today. Additive only: it never changes the
meaning of existing nodes or edges; it only adds ``APPLICATION`` nodes,
``BELONGS_TO`` edges, and per-app attributes.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.edge import UnifiedEdge
from agent_bom.graph.node import NodeDimensions, UnifiedNode
from agent_bom.graph.severity import SEVERITY_BUCKETS_ASPM, SEVERITY_RANK, SEVERITY_RISK_SCORE
from agent_bom.graph.types import EntityType, GraphSemanticLayer, RelationshipType

_OVERLAY_SOURCE = "aspm-overlay"

# Severity buckets we roll up per application, worst-first for deterministic
# ordering of the rolled-up counts attribute.
_SEVERITY_ORDER = SEVERITY_BUCKETS_ASPM

# Reachability verdicts a finding can carry after correlation. ``unknown`` is the
# honest default when no attack-path / exposure signal exists for the component —
# we never fabricate reachability.
_REACHABLE = "reachable"
_NOT_REACHABLE = "not_reachable"
_UNKNOWN = "unknown"

# Finding ``reachability`` strings the upstream scanners already emit that mean
# "the vulnerable code path is reachable". Kept conservative; anything else is
# treated as no-signal (→ unknown) rather than asserted not-reachable.
_REACHABLE_HINTS = frozenset({"reachable", "direct", "runtime", "exploitable", "confirmed"})
_NOT_REACHABLE_HINTS = frozenset({"unreachable", "not_reachable", "no_path"})

# Manifest / project-root markers. When a finding's source path contains one of
# these as a path segment, the directory *holding* it is treated as the
# application root, so sibling findings under the same project collapse to one
# app. Matched on the basename of each path segment.
_MANIFEST_FILES = frozenset(
    {
        "package.json",
        "requirements.txt",
        "pyproject.toml",
        "setup.py",
        "setup.cfg",
        "go.mod",
        "cargo.toml",
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
        "gemfile",
        "composer.json",
        "dockerfile",
        "pipfile",
        "poetry.lock",
        "package-lock.json",
        "yarn.lock",
    }
)


def _finding_field(finding: Any, name: str) -> Any:
    """Read a field from a ``Finding.to_dict()`` payload or a dataclass."""
    if isinstance(finding, dict):
        return finding.get(name)
    return getattr(finding, name, None)


def _finding_asset(finding: Any) -> dict[str, Any]:
    asset = _finding_field(finding, "asset")
    if isinstance(asset, dict):
        return asset
    return {}


def _norm_path(raw: Any) -> str:
    """Normalise a source path to forward slashes with no leading ``./``."""
    if not isinstance(raw, str):
        return ""
    text = raw.strip().replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text.strip("/")


def _manifest_roots(findings: list[Any]) -> list[str]:
    """Collect the directories that hold a manifest file across all findings.

    These are the project / service roots an application is anchored on. Returned
    longest-first so the most-specific (deepest) root wins when one project nests
    under another. Deterministic: sorted by depth then lexically.
    """
    roots: set[str] = set()
    for finding in findings:
        location = _norm_path(_finding_asset(finding).get("location"))
        if not location:
            continue
        segments = location.split("/")
        if segments[-1].lower() in _MANIFEST_FILES:
            roots.add("/".join(segments[:-1]))  # "" for a top-level manifest = repo root
    # Deepest (most path segments) first; the empty repo root sorts last.
    return sorted(roots, key=lambda r: (-(r.count("/") + 1) if r else 0, r))


def _app_identity(finding: Any, manifest_roots: list[str]) -> tuple[str, str]:
    """Derive ``(app_key, app_label)`` for a finding, deterministically.

    Resolution order (best-effort, all string-only — no filesystem access):

    1. The longest discovered manifest-root directory the finding's source path
       falls under, so *every* finding beneath a project root (deeply nested
       source files included) collapses to one application.
    2. Else the immediate directory of the source path (a standalone service /
       manifest root with no sibling manifest observed).
    3. Else the asset name (a server / image / repo name) when no path exists.

    ``app_key`` is a stable lower-cased identity; ``app_label`` is the
    human-facing name. Returns ``("", "")`` when nothing identifies an app.
    """
    asset = _finding_asset(finding)
    location = _norm_path(asset.get("location"))
    if location:
        segments = location.split("/")
        is_manifest = segments[-1].lower() in _MANIFEST_FILES
        # 1. Longest manifest root this path lives under (manifest_roots is
        #    pre-sorted deepest-first, so the first match is the most specific).
        for root in manifest_roots:
            if root == "" or location == root or location.startswith(root + "/"):
                return (root.lower(), root) if root else _repo_root(segments)
        # 2. No manifest root in play: the file's own directory is the root,
        #    or the repo root for a bare top-level file.
        if is_manifest or len(segments) > 1:
            root = "/".join(segments[:-1])
            if root:
                return root.lower(), root
        return _repo_root(segments)

    asset_name = asset.get("name")
    if isinstance(asset_name, str) and asset_name.strip():
        clean = asset_name.strip()
        return clean.lower(), clean
    return "", ""


def _repo_root(segments: list[str]) -> tuple[str, str]:
    """Top-level path segment as the repo-root application identity."""
    top = segments[0] if segments else ""
    return (top.lower(), top) if top else ("", "")


def _app_node_id(app_key: str) -> str:
    return f"application:{app_key}"


def _component_key(finding: Any) -> str:
    """Stable identity for the *component* a finding is about (within an app).

    Prefers the asset's canonical/stable id, then its identifier (purl / ARN /
    digest), then name + location. Used as part of the dedup tuple so the same
    package reported by two scanners dedupes, while two different packages do not.
    """
    asset = _finding_asset(finding)
    for field_name in ("stable_id", "canonical_id", "identifier"):
        val = asset.get(field_name)
        if isinstance(val, str) and val.strip():
            return val.strip().lower()
    name = str(asset.get("name") or "").strip().lower()
    location = _norm_path(asset.get("location")).lower()
    return f"{name}@{location}" if location else name


def _rule_key(finding: Any) -> str:
    """Stable identity for the *rule/vuln* a finding asserts.

    A CVE id when present (so the same CVE from SCA + container dedupes), else
    the finding's title (so the same rule dedupes across sources).
    """
    cve = _finding_field(finding, "cve_id")
    if isinstance(cve, str) and cve.strip():
        return cve.strip().lower()
    title = _finding_field(finding, "title")
    if isinstance(title, str) and title.strip():
        return title.strip().lower()
    ftype = _finding_field(finding, "finding_type")
    return str(ftype or "finding").lower()


def _finding_severity(finding: Any) -> str:
    """Normalised severity string for roll-up bucketing."""
    for field_name in ("effective_severity", "severity"):
        val = _finding_field(finding, field_name)
        if isinstance(val, str) and val.strip():
            low = val.strip().lower()
            if low in SEVERITY_RANK:
                return "info" if low == "informational" else low
    return _UNKNOWN


def _finding_node_id(graph: UnifiedGraph, finding: Any) -> str | None:
    """Resolve the existing graph node a finding's component maps to.

    Tries the vuln node id (``vuln:<CVE>``) and the asset's stable/canonical id
    against the graph. Returns the first id present in the graph, else ``None`` —
    the finding is still counted in the per-app roll-up, but no BELONGS_TO edge
    is drawn from a node that doesn't exist (the overlay never invents nodes).
    """
    cve = _finding_field(finding, "cve_id")
    candidates: list[str] = []
    if isinstance(cve, str) and cve.strip():
        candidates.append(f"vuln:{cve.strip()}")
    asset = _finding_asset(finding)
    for field_name in ("stable_id", "canonical_id"):
        val = asset.get(field_name)
        if isinstance(val, str) and val.strip():
            candidates.append(val.strip())
    for candidate in candidates:
        if graph.has_node(candidate):
            return candidate
    return None


def _attack_path_node_ids(graph: UnifiedGraph) -> set[str]:
    """Every node id that participates in a materialised attack path.

    Reuses the existing ``graph.attack_paths`` (written by attack-path fusion);
    a component on any chain is treated as reachable. No new traversal here.
    """
    reachable: set[str] = set()
    for path in graph.attack_paths:
        for hop in path.hops:
            if isinstance(hop, str) and hop:
                reachable.add(hop)
    return reachable


def _node_is_exposed(node: UnifiedNode | None) -> bool:
    if node is None:
        return False
    attrs = node.attributes
    return bool(
        attrs.get("internet_exposed")
        or attrs.get("toxic_exposed_vulnerable")
        or attrs.get("toxic_exposed_sensitive")
        or attrs.get("on_attack_path")
    )


def _reachability_verdict(
    finding: Any,
    node_id: str | None,
    graph: UnifiedGraph,
    attack_path_nodes: set[str],
) -> str:
    """Reachable / not-reachable / unknown for a finding, from existing signal.

    Reachable when: the finding's component node is on a materialised attack
    path, OR carries an exposure flag (internet-exposed / toxic combo), OR the
    finding itself reports a reachable code path. Not-reachable only when an
    upstream reachability analysis explicitly said so. Unknown otherwise — the
    overlay does not assert reachability it cannot back with existing data.
    """
    if node_id and node_id in attack_path_nodes:
        return _REACHABLE
    if node_id and _node_is_exposed(graph.get_node(node_id)):
        return _REACHABLE
    if _finding_field(finding, "is_actionable") is True:
        return _REACHABLE
    hint = _finding_field(finding, "reachability")
    if isinstance(hint, str) and hint.strip():
        low = hint.strip().lower()
        if low in _REACHABLE_HINTS:
            return _REACHABLE
        if low in _NOT_REACHABLE_HINTS:
            return _NOT_REACHABLE
    return _UNKNOWN


def _owner_for_app(app_key: str, owners_by_path: dict[str, str]) -> str:
    """Best-effort CODEOWNERS owner for an application root.

    ``owners_by_path`` maps a normalised path prefix → owner. The longest prefix
    that the app root starts under wins (CODEOWNERS most-specific-match
    semantics). Returns ``""`` when no rule matches.
    """
    if not owners_by_path:
        return ""
    best_prefix = ""
    best_owner = ""
    for prefix in sorted(owners_by_path):
        if app_key == prefix or app_key.startswith(prefix + "/") or prefix == "":
            if len(prefix) >= len(best_prefix):
                best_prefix = prefix
                best_owner = owners_by_path[prefix]
    return best_owner


def _load_owners(report_json: Any) -> dict[str, str]:
    """Parse an optional CODEOWNERS map carried on the report.

    Accepts ``report_json["codeowners"]`` as either a ``{path_prefix: owner}``
    dict or a list of ``{"path"/"pattern": ..., "owner"/"owners": ...}`` records.
    Absent ⇒ empty map ⇒ apps simply carry no owner. Never reads the filesystem.
    """
    raw = report_json.get("codeowners") if isinstance(report_json, dict) else None
    owners: dict[str, str] = {}
    if isinstance(raw, dict):
        for path, owner in raw.items():
            prefix = _norm_path(path).lower()
            if isinstance(owner, str) and owner.strip():
                owners[prefix] = owner.strip()
            elif isinstance(owner, (list, tuple)) and owner:
                owners[prefix] = ", ".join(str(o).strip() for o in owner if str(o).strip())
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, dict):
                continue
            prefix = _norm_path(entry.get("path") or entry.get("pattern")).lower()
            owner_val = entry.get("owner") or entry.get("owners")
            if isinstance(owner_val, (list, tuple)):
                owner_str = ", ".join(str(o).strip() for o in owner_val if str(o).strip())
            else:
                owner_str = str(owner_val or "").strip()
            if owner_str:
                owners[prefix] = owner_str
    return owners


def apply_aspm_overlay(
    graph: UnifiedGraph,
    report_json: dict[str, Any],
    now: datetime,
) -> dict[str, int]:
    """Correlate AppSec findings around applications, in place.

    Args:
        graph: the unified graph to enrich (mutated in place). Runs after the
            other overlays so it sees attack-path / exposure signals.
        report_json: the persisted AIBOM report JSON contract. Reads the
            optional ``findings`` block (a list of ``Finding.to_dict()`` dicts)
            and optional ``codeowners`` map. Never fetched here.
        now: reference time for the application nodes' timestamps (no inline
            ``datetime.now`` — determinism / testability).

    Returns counts of applications created, findings correlated, duplicates
    merged, and reachable findings flagged. A complete no-op (returns all-zero,
    graph untouched) when the report carries no findings or none derive an app.
    """
    zero = {"applications": 0, "correlated_findings": 0, "deduplicated": 0, "reachable": 0}
    raw_findings = report_json.get("findings") if isinstance(report_json, dict) else None
    if not isinstance(raw_findings, list) or not raw_findings:
        return zero
    findings = [f for f in raw_findings if isinstance(f, dict)]
    if not findings:
        return zero

    owners_by_path = _load_owners(report_json)
    attack_path_nodes = _attack_path_node_ids(graph)
    # Discover project/service roots once so deeply-nested source-file findings
    # collapse onto the manifest root that owns them, not their own sub-directory.
    manifest_roots = _manifest_roots(findings)

    # ── 1. Bucket findings per application, deduping within each app ─────────
    # dedup_key = (component_key, rule_key). Within one app, the first finding
    # for a dedup_key is the canonical occurrence; later ones only contribute
    # their reporting source to that occurrence's provenance.
    apps: dict[str, dict[str, Any]] = {}
    total_correlated = 0
    total_deduped = 0
    total_reachable = 0

    for finding in findings:
        app_key, app_label = _app_identity(finding, manifest_roots)
        if not app_key:
            continue
        total_correlated += 1
        app = apps.get(app_key)
        if app is None:
            app = {
                "label": app_label,
                "occurrences": {},  # dedup_key -> occurrence dict
                "node_ids": set(),  # graph node ids to attach via BELONGS_TO
            }
            apps[app_key] = app

        component = _component_key(finding)
        rule = _rule_key(finding)
        dedup_key = (component, rule)
        severity = _finding_severity(finding)
        source = str(_finding_field(finding, "source") or "unknown").lower()
        node_id = _finding_node_id(graph, finding)
        verdict = _reachability_verdict(finding, node_id, graph, attack_path_nodes)

        occurrences: dict[tuple[str, str], dict[str, Any]] = app["occurrences"]
        occ = occurrences.get(dedup_key)
        if occ is None:
            occ = {
                "component": component,
                "rule": rule,
                "severity": severity,
                "sources": {source} if source else set(),
                "reachability": verdict,
                "node_id": node_id,
            }
            occurrences[dedup_key] = occ
        else:
            total_deduped += 1
            if source:
                occ["sources"].add(source)
            # Worst severity across sources wins; keep the strongest reach signal.
            if SEVERITY_RANK.get(severity, 0) > SEVERITY_RANK.get(occ["severity"], 0):
                occ["severity"] = severity
            if verdict == _REACHABLE:
                occ["reachability"] = _REACHABLE
            elif verdict == _NOT_REACHABLE and occ["reachability"] == _UNKNOWN:
                occ["reachability"] = _NOT_REACHABLE
            if node_id and not occ["node_id"]:
                occ["node_id"] = node_id

        if node_id:
            app["node_ids"].add(node_id)

    if not apps:
        return zero

    # ── 2. Materialise APPLICATION nodes + per-app roll-up + BELONGS_TO ──────
    now_iso = now.isoformat()
    applications_created = 0
    for app_key in sorted(apps):
        app = apps[app_key]
        occurrences = app["occurrences"]

        severity_counts: dict[str, int] = {bucket: 0 for bucket in _SEVERITY_ORDER}
        risk_score = 0.0
        reachable_count = 0
        for occ in occurrences.values():
            bucket = occ["severity"] if occ["severity"] in severity_counts else _UNKNOWN
            severity_counts[bucket] += 1
            risk_score += SEVERITY_RISK_SCORE.get(occ["severity"], 0.0)
            if occ["reachability"] == _REACHABLE:
                reachable_count += 1
        total_reachable += reachable_count

        app_severity = _UNKNOWN
        for bucket in _SEVERITY_ORDER:
            if severity_counts.get(bucket):
                app_severity = bucket
                break

        owner = _owner_for_app(app_key, owners_by_path)
        app_node_id = _app_node_id(app_key)
        # Deterministic, sorted provenance list per app (which sources reported).
        all_sources: set[str] = set()
        for occ in occurrences.values():
            all_sources |= occ["sources"]

        node = UnifiedNode(
            id=app_node_id,
            entity_type=EntityType.APPLICATION,
            label=app["label"] or app_key,
            severity=app_severity if app_severity != _UNKNOWN else "",
            risk_score=round(risk_score, 6),
            first_seen=now_iso,
            last_seen=now_iso,
            attributes={
                "app_key": app_key,
                "owner": owner,
                "finding_count": len(occurrences),
                "severity_counts": {b: severity_counts[b] for b in _SEVERITY_ORDER},
                "aspm_risk_score": round(risk_score, 6),
                "reachable_finding_count": reachable_count,
                "finding_sources": sorted(all_sources),
                "component_count": len({occ["component"] for occ in occurrences.values()}),
            },
            data_sources=[_OVERLAY_SOURCE],
            dimensions=NodeDimensions(surface=GraphSemanticLayer.APP.value),
        )
        if app_node_id not in graph.nodes:
            applications_created += 1
        graph.add_node(node)

        # BELONGS_TO from each existing finding/component node → application.
        # Sorted for determinism; add_edge dedupes so applying twice is identical.
        belongs_node_ids: list[str] = sorted(str(nid) for nid in app["node_ids"])
        for belongs_source in belongs_node_ids:
            graph.add_edge(
                UnifiedEdge(
                    source=belongs_source,
                    target=app_node_id,
                    relationship=RelationshipType.BELONGS_TO,
                    evidence={"source": _OVERLAY_SOURCE, "app": app_key},
                )
            )

    return {
        "applications": applications_created,
        "correlated_findings": total_correlated,
        "deduplicated": total_deduped,
        "reachable": total_reachable,
    }
