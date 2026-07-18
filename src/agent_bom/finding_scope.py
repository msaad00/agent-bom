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

from collections.abc import Mapping
from typing import TYPE_CHECKING, Optional

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
    from agent_bom.finding import FindingSource, FindingType

    ev = evidence or {}

    if source in {FindingSource.CLOUD_CIS, FindingSource.CLOUD_SECURITY}:
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
    from agent_bom.finding import FindingSource, FindingType

    try:
        source = FindingSource(str(row.get("source") or "").upper())
        ftype = FindingType(str(row.get("finding_type") or "").upper())
    except ValueError:
        return None
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
    return security_domain_for(source, ftype, evidence)


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


def _is_iac_misconfig(source: "FindingSource", ftype: "FindingType", ev: dict) -> bool:
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
    from agent_bom.finding import FindingSource, FindingType

    ev = evidence or {}
    lenses: set[str] = {security_domain_for(source, finding_type, evidence)}

    is_code_or_secret = finding_type in (FindingType.SAST, FindingType.CREDENTIAL_EXPOSURE) or source in (
        FindingSource.SAST,
        FindingSource.SECRET_SCAN,
    )

    # Vulnerability-management lens.
    if finding_type in (FindingType.CVE, FindingType.MALICIOUS_PACKAGE, FindingType.LICENSE):
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

    from agent_bom.finding import FindingSource, FindingType

    try:
        source = FindingSource(str(row.get("source") or "").upper())
        ftype = FindingType(str(row.get("finding_type") or "").upper())
    except ValueError:
        return frozenset(lenses)
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
    return frozenset(lenses | security_lenses_for(source, ftype, evidence))


def row_matches_scope(row: dict, filters: Mapping[str, str]) -> bool:
    """Return True when a finding row matches every active scope filter.

    Single source of truth for the ``/v1/findings`` scope predicate, shared by
    the route (in-memory scan findings) and the hub store (bulk-ingested current
    rows) so the two paths can never diverge on the overlapping-lens semantics.

    ``provider`` / ``account_ref`` / ``environment`` are exact, lowercased
    equality checks. ``domain`` matches membership in the finding's overlapping
    coverage-lens set (:func:`lenses_for_row`), so ``domain=aspm`` returns
    SAST + secrets + repo dependencies + IaC and ``domain=vuln`` returns every
    CVE. The caller is responsible for pre-canonicalizing the filter values
    (lowercased/trimmed, ``appsec_sca`` -> ``aspm`` legacy alias applied).
    """
    for key in ("provider", "account_ref", "environment"):
        wanted = filters.get(key)
        if wanted is not None and str(row.get(key) or "").strip().lower() != wanted:
            return False
    wanted_domain = filters.get("domain")
    if wanted_domain is not None:
        lenses = lenses_for_row(row) or ({domain_for_row(row) or ""} if domain_for_row(row) else set())
        if wanted_domain not in lenses:
            return False
    return True
