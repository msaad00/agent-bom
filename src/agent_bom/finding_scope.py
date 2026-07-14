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

from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.finding import FindingSource, FindingType

# The five posture lanes. Kept as plain strings (not an enum) so the value can
# flow through JSON, the API, and the UI without a serialization shim.
SECURITY_DOMAINS: tuple[str, ...] = ("cspm", "vuln", "appsec_sca", "dspm", "aispm")

# Human labels for the UI coverage lanes (one per domain, 1:1).
SECURITY_DOMAIN_LABELS: dict[str, str] = {
    "cspm": "CSPM",
    "vuln": "Vuln mgmt",
    "appsec_sca": "AppSec / SCA",
    "dspm": "DSPM",
    "aispm": "AISPM",
}


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
         and secret findings are AppSec/SCA.
      3. Otherwise route by source (container/SBOM/external/filesystem → vuln;
         everything MCP/agent/runtime/prompt/skill/graph → AISPM).
    """
    from agent_bom.finding import FindingSource, FindingType

    ev = evidence or {}

    if source == FindingSource.CLOUD_CIS:
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

    if finding_type in (FindingType.SAST, FindingType.CREDENTIAL_EXPOSURE):
        return "appsec_sca"

    if source in (
        FindingSource.CONTAINER,
        FindingSource.SBOM,
        FindingSource.EXTERNAL,
        FindingSource.FILESYSTEM,
    ):
        return "vuln"

    if source in (FindingSource.SAST, FindingSource.SECRET_SCAN):
        return "appsec_sca"

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
    dom = str(row.get("security_domain") or "").strip().lower()
    if dom in SECURITY_DOMAINS:
        return dom
    from agent_bom.finding import FindingSource, FindingType

    try:
        source = FindingSource(str(row.get("source") or "").upper())
        ftype = FindingType(str(row.get("finding_type") or "").upper())
    except ValueError:
        return None
    evidence = row.get("evidence") if isinstance(row.get("evidence"), dict) else None
    return security_domain_for(source, ftype, evidence)
