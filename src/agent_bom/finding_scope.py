"""First-class scope + security-domain taxonomy for findings (issue #3946).

Two concerns live here, both pure and dependency-light so the ``Finding`` model
and ingest converters can import them without a cycle:

* **Scope** — where a finding lives: ``provider`` (aws/azure/gcp/snowflake/…),
  ``account_ref`` (a single normalized string such as ``aws:123456789012``),
  ``region``, and ``environment``. Cloud converters already know the provider
  and a resource id/ARN; these helpers parse the account/region out of an ARN
  and normalize the account into one canonical string.

* **Taxonomy** — which security domain a finding belongs to. Every finding maps
  to exactly one of the five posture lanes so the overview never double-counts a
  CIS misconfiguration as a CVE. The mapping leads with ``FindingType`` where it
  is decisive (a dependency CVE is vuln-management regardless of the scan entry
  point) and falls back to ``FindingSource`` for the runtime/agent signals.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Literal, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.finding import FindingSource, FindingType

# The five posture lanes. Kept as plain strings (not an enum) so the value can
# flow through JSON, the API, and the UI without a serialization shim. The
# posture-management family is symmetric: CSPM (cloud) · ASPM (application) ·
# DSPM (data) · AISPM (AI), with Vuln mgmt as the cross-surface CVE lane.
SECURITY_DOMAINS: tuple[str, ...] = ("cspm", "vuln", "aspm", "dspm", "aispm")

# Human labels for the UI coverage lanes (one per domain, 1:1).
SECURITY_DOMAIN_LABELS: dict[str, str] = {
    "cspm": "CSPM",
    "vuln": "Vuln mgmt",
    "aspm": "ASPM",
    "dspm": "DSPM",
    "aispm": "AISPM",
}

FindingClass = Literal["vulnerability", "misconfiguration", "secret", "identity", "unclassified"]
FINDING_CLASSES: tuple[FindingClass, ...] = (
    "vulnerability",
    "misconfiguration",
    "secret",
    "identity",
    "unclassified",
)

FindingSeverityFilter = Literal[
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "informational",
    "none",
    "unknown",
]
FINDING_SEVERITY_FILTERS: tuple[FindingSeverityFilter, ...] = (
    "critical",
    "high",
    "medium",
    "low",
    "info",
    "informational",
    "none",
    "unknown",
)

_VULNERABILITY_TYPES = {"CVE", "MALICIOUS_PACKAGE", "MALICIOUS_MODEL", "SAST"}
_MISCONFIGURATION_TYPES = {
    "CIS_FAIL",
    "CIS_ERROR",
    "CLOUD_BEST_PRACTICE_FAIL",
    "CLOUD_BEST_PRACTICE_ERROR",
}
_SECRET_TYPES = {"CREDENTIAL_EXPOSURE"}
_IDENTITY_TYPES = {"CIEM_OVER_PRIVILEGE"}

# Back-compat: rows persisted under the pre-rename ``appsec_sca`` key still
# resolve to the ``aspm`` lane so historical findings are never dropped.
_LEGACY_DOMAIN_ALIASES: dict[str, str] = {"appsec_sca": "aspm"}


def canonical_domain(value: str | None) -> Optional[str]:
    """Return a recognized posture-lane key for ``value``, applying legacy aliases.

    Accepts a stored/queried domain string, maps the pre-rename ``appsec_sca``
    alias to ``aspm``, and returns the canonical key only when it is one of the
    five posture lanes (else None so callers decide the default).
    """
    key = (value or "").strip().lower()
    key = _LEGACY_DOMAIN_ALIASES.get(key, key)
    return key if key in SECURITY_DOMAINS else None


def canonical_finding_severity_filter(value: object) -> str | None:
    """Validate and canonicalize the shared findings/report severity filter.

    ``informational`` is an accepted display alias for the persisted ``info``
    bucket. Invalid and non-string values fail closed rather than looking like
    a successful empty query.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("severity must be a string")
    normalized = value.strip().lower()
    if normalized not in FINDING_SEVERITY_FILTERS:
        raise ValueError(f"invalid severity '{value}'; accepted values: {', '.join(FINDING_SEVERITY_FILTERS)}")
    return "info" if normalized == "informational" else normalized


# ---------------------------------------------------------------------------
# Scope normalization
# ---------------------------------------------------------------------------


def account_ref_from_arn(arn: Optional[str]) -> Optional[str]:
    """Return the bare account id embedded in an AWS ARN, if present.

    ARN grammar is ``arn:partition:service:region:account-id:resource``. Some
    services (S3 buckets) leave the account segment empty; those return None.
    """
    if not arn or not isinstance(arn, str):
        return None
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn":
        return None
    account = parts[4].strip()
    return account or None


def region_from_arn(arn: Optional[str]) -> Optional[str]:
    """Return the region segment of an AWS ARN, if present."""
    if not arn or not isinstance(arn, str):
        return None
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn":
        return None
    region = parts[3].strip()
    return region or None


def normalize_account_ref(provider: Optional[str], account: Optional[str]) -> Optional[str]:
    """Return a single canonical account reference, e.g. ``aws:123456789012``.

    Idempotent: an already-prefixed value is returned with a normalized provider
    casing rather than double-prefixed. Empty/None inputs return None so the
    field stays nullable for non-cloud findings.
    """
    prov = (provider or "").strip().lower()
    acct = (account or "").strip()
    if not prov or not acct:
        return None
    if ":" in acct:
        head, _, tail = acct.partition(":")
        if head.strip().lower() == prov and tail.strip():
            return f"{prov}:{tail.strip()}"
    return f"{prov}:{acct}"


# ---------------------------------------------------------------------------
# Security-domain taxonomy
# ---------------------------------------------------------------------------


def security_domain_for(
    source: "FindingSource",
    finding_type: "FindingType",
    evidence: Optional[dict] = None,
) -> str:
    """Map a finding to exactly one of :data:`SECURITY_DOMAINS`.

    Precedence:
      1. Cloud posture sources route by data-vs-config: a Snowflake *governance*
         finding (data access risk, no CIS benchmark marker) is DSPM; every
         other cloud CIS finding is CSPM.
      2. ``FindingType`` is decisive for the portable signals — a dependency CVE
         or malicious package is vuln-management wherever it was discovered; SAST
         and secret-in-code findings are application-security posture (ASPM).
      3. Otherwise route by source (container/SBOM/external/filesystem → vuln;
         everything MCP/agent/runtime/prompt/skill/graph → AISPM).
    """
    return _security_domain(source, finding_type, evidence) or "aispm"


def _security_domain(
    source: "FindingSource | None",
    finding_type: "FindingType",
    evidence: Optional[dict] = None,
) -> Optional[str]:
    """:func:`security_domain_for`, but tolerant of an unknown source.

    A finding can arrive with a provenance label that is not a
    :class:`FindingSource` — every row ingested through ``POST
    /v1/findings/bulk`` does, because that endpoint's ``source`` is a free-text
    connector label whose default is ``"api"``. The type-decisive rules do not
    need the source at all: a CVE is vulnerability management wherever it came
    from. Only the source-routed fallbacks are skipped, and this returns None
    rather than guessing a lane when the type alone cannot decide.

    Kept as the single implementation of the precedence chain so the row-level
    and object-level entry points can never drift apart.
    """
    from agent_bom.finding import FindingSource, FindingType

    ev = evidence or {}

    # Content-confirmed data sensitivity is the data-security-posture lane,
    # decisive by type/source regardless of which provider surfaced it.
    if source is FindingSource.DSPM or finding_type is FindingType.SENSITIVE_DATA:
        return "dspm"

    if source is not None and source in {FindingSource.CLOUD_CIS, FindingSource.CLOUD_SECURITY}:
        provider = str(ev.get("provider") or "").strip().lower()
        # Snowflake governance findings carry a category + no CIS benchmark tag;
        # they describe data-access posture, not infra config → DSPM.
        if provider == "snowflake" and not ev.get("benchmark") and ev.get("category"):
            return "dspm"
        return "cspm"

    if finding_type in (
        FindingType.CVE,
        FindingType.MALICIOUS_PACKAGE,
        FindingType.LICENSE,
    ):
        return "vuln"

    # Cloud identity entitlement right-sizing is cloud-posture (CSPM), decisive by
    # type regardless of the graph-analysis source that derived it.
    if finding_type is FindingType.CIEM_OVER_PRIVILEGE:
        return "cspm"

    if finding_type in (FindingType.SAST, FindingType.CREDENTIAL_EXPOSURE):
        return "aspm"

    if source is None:
        # Nothing type-decisive matched and there is no source to route by.
        # Saying "unknown" is the honest answer; the caller decides the default.
        return None

    if source in (
        FindingSource.CONTAINER,
        FindingSource.SBOM,
        FindingSource.EXTERNAL,
        FindingSource.FILESYSTEM,
    ):
        return "vuln"

    if source in (FindingSource.SAST, FindingSource.SECRET_SCAN):
        return "aspm"

    # MCP scan, proxy, skill, browser-ext, prompt scan, graph correlation, and
    # any AI-native finding type (tool drift, injection, cloaking, blocklist,
    # combination, rate limit) are AI security-posture signals.
    return "aispm"


def domain_for_row(row: dict) -> Optional[str]:
    """Return the security domain for a serialized finding row, or None.

    Prefers the first-class ``security_domain`` field; falls back to the
    source/type mapping for legacy rows. Returns None when neither the field nor
    a recognizable source/type is present, so callers decide the default.
    """
    dom = canonical_domain(row.get("security_domain"))
    if dom is not None:
        return dom
    source, ftype = _parse_row_source_and_type(row)
    if ftype is None:
        return None
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
    return _security_domain(source, ftype, evidence)


def _parse_row_source_and_type(row: dict) -> tuple[Optional["FindingSource"], Optional["FindingType"]]:
    """Parse a serialized row's source and type INDEPENDENTLY.

    These used to be parsed in one ``try`` block, so an unrecognized source
    discarded a perfectly good finding type. Every row from ``POST
    /v1/findings/bulk`` hits that: its ``source`` is a free-text connector label
    (default ``"api"``), not a :class:`FindingSource`. The result was that a row
    plainly typed ``CVE`` derived no domain and no lenses, so every ``?domain=``
    query returned nothing for connector-ingested findings — while the same
    finding discovered by a scan filtered correctly.

    An unknown source is now just an unknown source.
    """
    from agent_bom.finding import FindingSource, FindingType

    try:
        source: Optional[FindingSource] = FindingSource(str(row.get("source") or "").upper())
    except ValueError:
        source = None
    try:
        ftype: Optional[FindingType] = FindingType(str(row.get("finding_type") or "").upper())
    except ValueError:
        ftype = None
    return source, ftype


# ---------------------------------------------------------------------------
# Coverage lenses (overlapping posture disciplines)
# ---------------------------------------------------------------------------
#
# ``security_domain_for`` picks the single PRIMARY lane a finding is stored and
# displayed under. The coverage lanes on the overview, however, are *overlapping
# posture lenses*, not a strict one-lane-per-finding partition: a single repo
# dependency CVE is both a vulnerability-management concern (``vuln``) and an
# application-security-posture concern (``aspm``). ``security_lenses_for``
# returns the SET of lenses a finding belongs to. It derives entirely from the
# same ``(source, finding_type, evidence)`` inputs the primary mapping uses — no
# schema migration. The primary is always a member of the set.
#
# Because lanes overlap, the sum of lane counts is NOT the total finding count.
# The exec headline / grade histogram is computed independently over the unified
# findings spine (once per finding), never by summing lenses.


def _is_iac_misconfig(source: "FindingSource | None", ftype: "FindingType", ev: dict) -> bool:
    """True when a misconfiguration finding describes infrastructure-as-code.

    IaC template scanning (Terraform / CloudFormation / K8s manifests in a repo)
    is an application/code-layer concern, so such misconfigs also belong to the
    ``aspm`` lens even though their primary cloud-config lane is ``cspm``.
    Detected from evidence markers only — absent a marker this never fires, so
    live-cloud CIS findings stay purely ``cspm``.
    """
    from agent_bom.finding import FindingType

    if ftype != FindingType.CIS_FAIL:
        return False
    if ev.get("iac"):
        return True
    marker = " ".join(str(ev.get(key) or "") for key in ("category", "scan_type", "framework", "resource_type", "source_kind")).lower()
    return any(token in marker for token in ("iac", "terraform", "cloudformation", "k8s manifest", "kubernetes manifest"))


def security_lenses_for(
    source: "FindingSource",
    finding_type: "FindingType",
    evidence: Optional[dict] = None,
) -> frozenset[str]:
    """Return the SET of overlapping coverage lenses a finding belongs to.

    Predicates (all derived from the primary mapping's inputs):

      * ``vuln`` — the vulnerability-management discipline: a CVE, malicious
        package, or license finding, or any dependency/package scanner output
        (container / SBOM / external / filesystem) that is not itself a
        code/secret finding.
      * ``aspm`` — the application/code/repo layer: SAST, secret/credential
        scanning, a repo/project-checkout dependency graph (SBOM / filesystem),
        and IaC misconfiguration. So a repo dependency CVE is in {vuln, aspm}.
      * ``cspm`` / ``dspm`` / ``aispm`` — carried by the primary mapping
        (cloud config, data governance, and AI/agent signals respectively).

    The primary lane is always included.
    """
    return _security_lenses(source, finding_type, evidence)


def _security_lenses(
    source: "FindingSource | None",
    finding_type: "FindingType",
    evidence: Optional[dict] = None,
) -> frozenset[str]:
    """:func:`security_lenses_for`, tolerant of an unknown source.

    Same reasoning as :func:`_security_domain`: the type-decisive lenses hold
    whatever the provenance label says, and only the source-routed ones are
    skipped. One implementation, so a bulk-ingested CVE and a scanned one land
    in the same lenses.
    """
    from agent_bom.finding import FindingSource, FindingType

    ev = evidence or {}
    lenses: set[str] = set()
    primary = _security_domain(source, finding_type, evidence)
    if primary is not None:
        lenses.add(primary)

    is_code_or_secret = finding_type in (FindingType.SAST, FindingType.CREDENTIAL_EXPOSURE) or source in (
        FindingSource.SAST,
        FindingSource.SECRET_SCAN,
    )

    # Vulnerability-management lens.
    if finding_type in (FindingType.CVE, FindingType.MALICIOUS_PACKAGE, FindingType.MALICIOUS_MODEL, FindingType.LICENSE):
        lenses.add("vuln")
    if not is_code_or_secret and source in (
        FindingSource.CONTAINER,
        FindingSource.SBOM,
        FindingSource.EXTERNAL,
        FindingSource.FILESYSTEM,
    ):
        lenses.add("vuln")

    # Application-security-posture lens.
    if is_code_or_secret:
        lenses.add("aspm")
    # A repo / project checkout dependency graph is application-layer, so its
    # dependency findings are ASPM as well as vuln.
    if source in (FindingSource.SBOM, FindingSource.FILESYSTEM):
        lenses.add("aspm")
    if _is_iac_misconfig(source, finding_type, ev):
        lenses.add("aspm")

    return frozenset(lenses)


def lenses_for_row(row: dict) -> frozenset[str]:
    """Return the overlapping coverage-lens set for a serialized finding row.

    Mirrors :func:`domain_for_row`: the stored ``security_domain`` (canonical,
    legacy-aliased) is always in the set, and — when the row carries a parseable
    source/type — the full derived lens set is unioned in. A row bearing a CVE id
    always counts under ``vuln``. Returns an empty set only when nothing is
    resolvable, so callers can fall back to a default lane.
    """
    lenses: set[str] = set()
    primary = canonical_domain(row.get("security_domain"))
    if primary is not None:
        lenses.add(primary)
    if str(row.get("cve_id") or "").strip():
        lenses.add("vuln")

    source, ftype = _parse_row_source_and_type(row)
    if ftype is None:
        return frozenset(lenses)
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
    return frozenset(lenses | _security_lenses(source, ftype, evidence))


def finding_class_for_row(row: Mapping[str, object]) -> FindingClass:
    """Return the user-facing issue class for a serialized finding.

    Classification is deliberately conservative. Only explicit finding types,
    sources, or vulnerability identifiers map to a class; an unknown finding
    is returned as the explicit ``unclassified`` bucket instead of disappearing
    from the taxonomy or silently appearing as a vulnerability.
    """
    finding_type = str(row.get("finding_type") or "").strip().upper()
    source = str(row.get("source") or "").strip().upper()
    identifier = str(row.get("cve_id") or row.get("vulnerability_id") or "").strip().upper()

    if finding_type in _SECRET_TYPES or source == "SECRET_SCAN":
        return "secret"
    if finding_type in _IDENTITY_TYPES:
        return "identity"
    if finding_type in _MISCONFIGURATION_TYPES or source in {"CLOUD_CIS", "CLOUD_SECURITY"}:
        return "misconfiguration"
    if finding_type in _VULNERABILITY_TYPES or source == "SAST" or identifier.startswith(("CVE-", "GHSA-")):
        return "vulnerability"
    return "unclassified"


_CANONICAL_NULLABLE_FINDING_FIELDS: tuple[str, ...] = (
    "source",
    "scan_id",
    "first_seen",
    "last_seen",
    "last_observed",
    "occurrence_count",
    "status",
    "lifecycle_status",
    "cvss_score",
    "cvss_version",
    "cvss_vector",
    "epss_score",
    "is_kev",
    "fixed_version",
    "remediation_versions",
    "remediation_guidance",
    "provenance",
    "owner",
    "sla_due_at",
    "graph_reachable",
    "graph_min_hop_distance",
    # --verify-integrity verdict. Explicit null = the check never ran, which is
    # a different claim from a failed verification.
    "package_integrity_verified",
    "package_provenance_attested",
    "package_provenance_source",
    # ``unavailable`` beside a null ``package_provenance_attested`` is a
    # registry that never answered, which is not a negative verdict.
    "package_provenance_status",
)

_FINDING_RESPONSE_TIMESTAMPS = (
    "first_seen",
    "last_seen",
    "last_observed",
    "resolved_at",
    "reopened_at",
    "sla_due_at",
)
_FINDING_RESPONSE_PROVENANCE_KEYS = frozenset(
    {
        "source",
        "source_type",
        "collector",
        "provider",
        "service",
        "observed_via",
        "observed_at",
        "confidence",
        "scan_id",
        "job_id",
        "schema_version",
    }
)
_FINDING_SEARCH_FIELDS = (
    "id",
    "canonical_id",
    "title",
    "cve_id",
    "vulnerability_id",
    "ghsa_id",
    "advisory_id",
    "package",
    "package_name",
    "agent",
    "agent_name",
    "source",
    "finding_type",
    "rule_id",
    "control_id",
    "resource_name",
)
_CVSS_VECTOR_RE = re.compile(r"^[A-Za-z0-9.:/_-]{1,256}$")
_STRUCTURAL_TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+ -]{0,511}$")
_LIFECYCLE_STATUSES = frozenset({"open", "reopened", "resolved", "suppressed", "accepted", "not_affected", "fixed"})


def _safe_timestamp(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or len(text) > 64:
        return None
    try:
        datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return text


def _safe_optional_text(value: Any, *, max_len: int) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    from agent_bom.security import sanitize_text

    return sanitize_text(value.strip(), max_len=max_len)


def _safe_finding_provenance(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, Mapping):
        return None
    from agent_bom.security import sanitize_sensitive_payload

    bounded = {str(key): raw for key, raw in value.items() if str(key) in _FINDING_RESPONSE_PROVENANCE_KEYS}
    sanitized = sanitize_sensitive_payload(bounded, max_str_len=128)
    if not isinstance(sanitized, dict):
        return None
    return sanitized or None


def _safe_structural_text(value: Any, *, max_len: int) -> str | None:
    """Return a bounded display identifier, never a path or credential value."""
    safe = _safe_optional_text(value, max_len=max_len)
    if safe is None or not _STRUCTURAL_TOKEN_RE.fullmatch(safe):
        return None
    return safe


def _safe_asset_projection(value: Any) -> dict[str, str] | None:
    """Project only the asset fields required to identify a finding in the UI.

    Raw identifiers and locations can contain account ids, local paths, URLs, or
    credentials. They remain default-deny. The human label, type, and stable
    opaque id are enough to avoid a meaningless ``asset`` placeholder while
    preserving the response's privacy boundary.
    """
    if not isinstance(value, Mapping):
        return None
    result: dict[str, str] = {}
    name = _safe_optional_text(value.get("name"), max_len=256)
    if name is not None and not name.startswith("<"):
        result["name"] = name
    for key, max_len in (("asset_type", 64), ("stable_id", 128)):
        safe = _safe_structural_text(value.get(key), max_len=max_len)
        if safe is not None:
            result[key] = safe
    if not result:
        return None
    return result


def _safe_control_projection(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    controls: list[dict[str, Any]] = []
    for raw in value[:100]:
        if not isinstance(raw, Mapping):
            continue
        framework = _safe_structural_text(raw.get("framework"), max_len=64)
        control = _safe_structural_text(
            raw.get("control") or raw.get("control_id") or raw.get("id"),
            max_len=128,
        )
        if framework is None or control is None:
            continue
        item: dict[str, Any] = {"framework": framework, "control": control}
        for key in ("version", "source", "via"):
            safe = _safe_structural_text(raw.get(key), max_len=128)
            if safe is not None:
                item[key] = safe
        confidence = raw.get("confidence")
        if isinstance(confidence, int | float) and not isinstance(confidence, bool):
            score = float(confidence)
            if math.isfinite(score) and 0.0 <= score <= 1.0:
                item["confidence"] = score
        controls.append(item)
    return controls


def safe_finding_response_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return the canonical public finding projection without replay-only data.

    Tier-A redaction remains the default-deny base. A narrow set of validated
    structural fields is restored explicitly so list and export surfaces expose
    authoritative lifecycle/advisory metadata without leaking descriptions,
    local paths, raw evidence, or private resource identifiers.
    """
    from agent_bom.evidence import EvidenceTier, redact_for_persistence
    from agent_bom.security import mask_email

    redacted = redact_for_persistence(dict(row), EvidenceTier.SAFE_TO_STORE)
    payload = dict(redacted) if isinstance(redacted, dict) else {}

    asset = _safe_asset_projection(row.get("asset"))
    if asset is not None:
        payload["asset"] = asset

    framework_tags = row.get("framework_tags")
    if isinstance(framework_tags, list):
        safe_tags = [safe for value in framework_tags[:200] if (safe := _safe_structural_text(value, max_len=128)) is not None]
        if safe_tags:
            payload["framework_tags"] = safe_tags

    controls = _safe_control_projection(row.get("controls"))
    if controls:
        payload["controls"] = controls

    for key in _FINDING_RESPONSE_TIMESTAMPS:
        safe_value = _safe_timestamp(row.get(key))
        if safe_value is not None:
            payload[key] = safe_value

    occurrence = row.get("occurrence_count", row.get("scan_count"))
    if isinstance(occurrence, int) and not isinstance(occurrence, bool) and 0 <= occurrence <= 2**63 - 1:
        payload["occurrence_count"] = occurrence
        payload["scan_count"] = occurrence

    ordinal = row.get("bulk_ordinal")
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and 0 <= ordinal <= 2**63 - 1:
        payload["bulk_ordinal"] = ordinal

    lifecycle_status = str(row.get("lifecycle_status") or row.get("status") or "").strip().lower()
    if lifecycle_status in _LIFECYCLE_STATUSES:
        payload["status"] = lifecycle_status
        payload["lifecycle_status"] = lifecycle_status

    for key, max_len in (
        ("source", 64),
        ("scan_id", 128),
        ("canonical_id", 512),
        ("origin", 64),
        ("batch_id", 128),
        ("cvss_version", 16),
    ):
        safe_value = _safe_optional_text(row.get(key), max_len=max_len)
        if safe_value is not None:
            payload[key] = safe_value

    vector = row.get("cvss_vector")
    if isinstance(vector, str) and _CVSS_VECTOR_RE.fullmatch(vector.strip()):
        payload["cvss_vector"] = vector.strip()

    epss = row.get("epss_score")
    if isinstance(epss, int | float) and not isinstance(epss, bool):
        score = float(epss)
        if math.isfinite(score) and 0.0 <= score <= 1.0:
            payload["epss_score"] = score
    if isinstance(row.get("is_kev"), bool):
        payload["is_kev"] = row["is_kev"]

    graph_distance = row.get("graph_min_hop_distance")
    payload["graph_min_hop_distance"] = (
        graph_distance
        if isinstance(graph_distance, int) and not isinstance(graph_distance, bool) and 0 <= graph_distance <= 10_000
        else None
    )
    graph_agents = row.get("graph_reachable_from_agents")
    payload["graph_reachable_from_agents"] = [
        agent_id
        for value in (graph_agents[:100] if isinstance(graph_agents, list) else [])
        if (agent_id := _safe_optional_text(value, max_len=512)) is not None
    ]

    # "Reachable" is not a free-standing opinion: `dependency_reach` defines it
    # as `bool(reachable_from)`, and the engine stamps the agent list from the
    # same report that sets the flag. A row asserting reachability while naming
    # nobody therefore contradicts the word, and would still collect
    # RISK_REACHABLE_BOOST and outrank findings the engine actually proved.
    # `None` is the model's documented "engine did not run" state and leaves
    # scoring untouched, so an unsupported claim costs nothing rather than
    # buying rank. Checked against the sanitised list, not the raw one.
    #
    # `False` is deliberately still accepted: a genuinely unreachable finding
    # carries no corroborating fields either, so rejecting it would break
    # round-trip of our own export. Telling those apart needs a provenance
    # field saying the engine ran.
    graph_reachable = row.get("graph_reachable")
    if not isinstance(graph_reachable, bool):
        payload["graph_reachable"] = None
    elif graph_reachable and not payload["graph_reachable_from_agents"]:
        payload["graph_reachable"] = None
    else:
        payload["graph_reachable"] = graph_reachable

    remediation_versions = row.get("remediation_versions")
    if not isinstance(remediation_versions, list):
        remediation_versions = row.get("fixed_versions")
    if not isinstance(remediation_versions, list):
        fixed_version = row.get("fixed_version")
        remediation_versions = [fixed_version] if isinstance(fixed_version, str) else []
    safe_versions = [safe for value in remediation_versions[:50] if (safe := _safe_optional_text(value, max_len=128)) is not None]
    if safe_versions:
        payload["remediation_versions"] = safe_versions

    # Supply-chain verification verdict (--verify-integrity). Structural and
    # non-sensitive — two booleans and two short enum-like tokens — so it is
    # restored past the default-deny redaction rather than lost with the raw
    # evidence bag it travels in.
    raw_evidence = row.get("evidence")
    verdict_evidence: Mapping[str, Any] = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    for key in ("package_integrity_verified", "package_provenance_attested"):
        value = row.get(key, verdict_evidence.get(key))
        if isinstance(value, bool):
            payload[key] = value
    for key in ("package_provenance_source", "package_provenance_status"):
        token = _safe_optional_text(row.get(key, verdict_evidence.get(key)), max_len=64)
        if token is not None:
            payload[key] = token

    provenance = _safe_finding_provenance(row.get("provenance"))
    if provenance is not None:
        payload["provenance"] = provenance

    owner = _safe_optional_text(row.get("owner"), max_len=200)
    if owner is not None:
        payload["owner"] = mask_email(owner)

    return canonical_finding_payload(payload)


def canonical_finding_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """Return a finding row with the additive, evidence-honest API contract.

    Missing evidence stays explicit ``None``. Existing authoritative values are
    never replaced, and aliases are derived only from semantically equivalent
    persisted fields (``last_seen`` and ``scan_count``).
    """
    payload = dict(row)
    payload["finding_class"] = finding_class_for_row(payload)
    for key in _CANONICAL_NULLABLE_FINDING_FIELDS:
        payload.setdefault(key, None)

    if payload["last_observed"] is None and payload["last_seen"] is not None:
        payload["last_observed"] = payload["last_seen"]
    if payload["occurrence_count"] is None and payload.get("scan_count") is not None:
        payload["occurrence_count"] = payload["scan_count"]
    if payload["lifecycle_status"] is None and payload["status"] is not None:
        payload["lifecycle_status"] = payload["status"]
    if payload["remediation_versions"] is None:
        fixed_versions = payload.get("fixed_versions")
        if isinstance(fixed_versions, list):
            payload["remediation_versions"] = fixed_versions
        elif isinstance(payload["fixed_version"], str) and payload["fixed_version"].strip():
            payload["remediation_versions"] = [payload["fixed_version"]]

    # Remediation SLA — one source of truth (agent_bom.graph.sla). Any row that
    # reaches the API without a precomputed value (bulk-ingested / hub findings)
    # is filled here so ``/v1/findings``, the CLI, the exports, and the UI read
    # the same deadline the scan spine already carries. Owner stays an explicit
    # ``None`` when nobody is assigned (rendered "Unassigned" only in the CLI/UI);
    # the deadline stays ``None`` when no anchor or KEV date makes one derivable,
    # never a fabricated date.
    from agent_bom.graph.sla import sla_due_at

    if payload["sla_due_at"] is None:
        anchor = payload.get("first_seen") or payload.get("last_seen") or payload.get("last_observed")
        evidence = payload.get("evidence")
        kev_due_date = payload.get("kev_due_date")
        if kev_due_date is None and isinstance(evidence, Mapping):
            kev_due_date = evidence.get("kev_due_date")
        payload["sla_due_at"] = sla_due_at(
            payload.get("effective_severity") or payload.get("severity"),
            anchor,
            kev_due_date=kev_due_date,
        )
    return payload


def row_matches_search(row: Mapping[str, object], query: str | None) -> bool:
    """Match the server-backed finding search over safe structural fields."""
    needle = str(query or "").strip().casefold()
    if not needle:
        return True
    for key in _FINDING_SEARCH_FIELDS:
        value = row.get(key)
        if isinstance(value, str) and needle in value.casefold():
            return True
        if isinstance(value, list) and any(needle in str(item).casefold() for item in value):
            return True
    return False


def _framework_control_codes(row: Mapping[str, Any], tag_field: str, framework_key: str) -> set[str]:
    """Collect one framework's control codes from every representation on a row.

    A scan finding may carry its framework controls three ways: the per-framework
    tag list (``soc2_tags``), the structured ``controls`` list, and the flattened
    ``framework_tags`` (``"soc2:CC6.1"``). All are read, but strictly scoped to
    ``framework_key`` so a code is never matched against another framework's
    namespace — the flat ``compliance_tags`` union is deliberately NOT consulted.
    """
    codes: set[str] = set()
    raw = row.get(tag_field)
    if isinstance(raw, (list, tuple, set)):
        codes.update(str(tag) for tag in raw)
    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict) and str(control.get("framework") or "") == framework_key:
                code = control.get("control") or control.get("id")
                if code:
                    codes.add(str(code))
    framework_tags = row.get("framework_tags")
    if isinstance(framework_tags, list):
        prefix = f"{framework_key}:"
        for tag in framework_tags:
            text = str(tag)
            if text.startswith(prefix):
                codes.add(text[len(prefix) :])
    return codes


def _row_matches_framework(row: Mapping[str, Any], filters: Mapping[str, str]) -> bool:
    """Framework / control drill-through predicate (compliance → findings).

    The framework identifier is resolved once in the route to ``framework_tag_field``
    (e.g. ``soc2_tags``) plus the canonical ``framework_slug``. When it does not
    resolve the route stores the raw value under ``framework`` and nothing can
    match it — an honest empty result rather than a silent widening.

    With a ``control`` code the match is exact containment in the framework's
    control codes, mirroring the compliance per-control count (``code in tags``)
    so the drilled queue reconciles with the badge the user clicked. Without a
    control it is a framework-level match: any control tagged for the framework,
    or — for bulk-ingested rows whose per-framework tags are redacted at rest —
    the framework slug present in ``applicable_frameworks``.
    """
    tag_field = filters.get("framework_tag_field")
    if tag_field is None:
        # Unresolved framework identifier: match nothing (honest empty).
        return False

    control = filters.get("control")
    control = control.strip() if isinstance(control, str) else None
    framework_key = tag_field[:-5] if tag_field.endswith("_tags") else tag_field
    codes = _framework_control_codes(row, tag_field, framework_key)

    if control:
        return control in codes
    if codes:
        return True
    slug = filters.get("framework_slug")
    if slug:
        from agent_bom.compliance_coverage import normalize_framework_slug

        wanted = normalize_framework_slug(slug)
        applicable = row.get("applicable_frameworks")
        if isinstance(applicable, (list, tuple, set)):
            return any(normalize_framework_slug(str(item)) == wanted for item in applicable)
    return False


def row_matches_scope(row: dict, filters: Mapping[str, str]) -> bool:
    """Return True when a finding row matches every active scope filter.

    Single source of truth for the ``/v1/findings`` scope predicate, shared by
    the route (in-memory scan findings) and the hub store (bulk-ingested current
    rows) so the two paths can never diverge on the overlapping-lens semantics.

    ``provider`` / ``account_ref`` / ``environment`` are exact, lowercased
    equality checks. ``domain`` matches membership in the finding's overlapping
    coverage-lens set (:func:`lenses_for_row`), so ``domain=aspm`` returns
    SAST + secrets + repo dependencies + IaC and ``domain=vuln`` returns every
    CVE. ``framework`` / ``control`` power the compliance drill-through
    (:func:`_row_matches_framework`). The caller is responsible for
    pre-canonicalizing the filter values (lowercased/trimmed, ``appsec_sca`` ->
    ``aspm`` legacy alias applied, framework resolved to its tag field).
    """
    for key in ("provider", "account_ref", "environment"):
        wanted = filters.get(key)
        if wanted is not None and str(row.get(key) or "").strip().lower() != wanted:
            return False
    wanted_owner = filters.get("owner")
    if wanted_owner is not None and str(row.get("owner") or "").strip().lower() != wanted_owner:
        return False
    wanted_sla = filters.get("sla")
    if wanted_sla is not None:
        raw_due_at = str(row.get("sla_due_at") or "").strip()
        if wanted_sla == "unassigned":
            if raw_due_at:
                return False
        else:
            if not raw_due_at:
                return False
            try:
                due_at = datetime.fromisoformat(raw_due_at.replace("Z", "+00:00"))
            except ValueError:
                return False
            if due_at.tzinfo is None:
                due_at = due_at.replace(tzinfo=timezone.utc)
            overdue = due_at <= datetime.now(timezone.utc)
            if (wanted_sla == "overdue") is not overdue:
                return False
    wanted_domain = filters.get("domain")
    if wanted_domain is not None:
        lenses = lenses_for_row(row) or ({domain_for_row(row) or ""} if domain_for_row(row) else set())
        if wanted_domain not in lenses:
            return False
    wanted_class = filters.get("finding_class")
    if wanted_class is not None and finding_class_for_row(row) != wanted_class:
        return False
    # Compliance drill-through: framework (resolved to its tag field) + optional
    # control code. ``framework`` (raw) is present only when the identifier did
    # not resolve, in which case the match is an honest empty.
    if filters.get("framework_tag_field") is not None or filters.get("framework") is not None:
        if not _row_matches_framework(row, filters):
            return False
    # KEV leads the executive headline — "actively exploited, fix these first" —
    # so the list has to be able to answer it. An absent verdict is not a match:
    # a row nobody checked must never be presented as known-exploited.
    wanted_kev = filters.get("kev")
    if wanted_kev is not None:
        if (row.get("is_kev") is True) is not (str(wanted_kev).strip().lower() in {"true", "1", "yes"}):
            return False
    if not row_matches_search(row, filters.get("q")):
        return False
    return True
