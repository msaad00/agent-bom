"""Compatibility exports and I/O adapters for the pure version kernel.

Version decisions live in ``agent_bom.core.versions``. This adapter preserves
scan-warning delivery and registry metadata lookups at their existing import path.
"""

from __future__ import annotations

import logging
from functools import lru_cache
from urllib.parse import quote as _url_quote

from agent_bom.core.packages import encode_go_module_path as _go_encode_module
from agent_bom.core.versions.distro import (
    _APK_POST_SUFFIXES as _APK_POST_SUFFIXES,
)
from agent_bom.core.versions.distro import (
    _APK_PRE_SUFFIXES as _APK_PRE_SUFFIXES,
)
from agent_bom.core.versions.distro import (
    _APK_SUFFIX_RE as _APK_SUFFIX_RE,
)
from agent_bom.core.versions.distro import (
    _apk_split_suffix as _apk_split_suffix,
)
from agent_bom.core.versions.distro import (
    _apk_suffix_key as _apk_suffix_key,
)
from agent_bom.core.versions.distro import (
    _apk_suffix_rank as _apk_suffix_rank,
)
from agent_bom.core.versions.distro import (
    _compare_apk_suffix_keys as _compare_apk_suffix_keys,
)
from agent_bom.core.versions.distro import (
    _compare_apk_versions as _compare_apk_versions,
)
from agent_bom.core.versions.distro import (
    _compare_debian_part as _compare_debian_part,
)
from agent_bom.core.versions.distro import (
    _compare_debian_versions as _compare_debian_versions,
)
from agent_bom.core.versions.distro import (
    _compare_rpm_like as _compare_rpm_like,
)
from agent_bom.core.versions.distro import (
    _compare_rpm_versions as _compare_rpm_versions,
)
from agent_bom.core.versions.distro import (
    _consume_rpm_segment as _consume_rpm_segment,
)
from agent_bom.core.versions.distro import (
    _debian_order_char as _debian_order_char,
)
from agent_bom.core.versions.distro import (
    _split_debian_version as _split_debian_version,
)
from agent_bom.core.versions.distro import (
    _split_epoch as _split_epoch,
)
from agent_bom.core.versions.go import (
    _compare_go_versions as _compare_go_versions,
)
from agent_bom.core.versions.go import (
    _go_packaging_operand as _go_packaging_operand,
)
from agent_bom.core.versions.go import (
    _go_pseudo_timestamp as _go_pseudo_timestamp,
)
from agent_bom.core.versions.maven import (
    _MAVEN_ALIASES as _MAVEN_ALIASES,
)
from agent_bom.core.versions.maven import (
    _MAVEN_QUALIFIERS as _MAVEN_QUALIFIERS,
)
from agent_bom.core.versions.maven import (
    _MAVEN_RELEASE_INDEX as _MAVEN_RELEASE_INDEX,
)
from agent_bom.core.versions.maven import (
    _MAVEN_SHORT_QUALIFIERS as _MAVEN_SHORT_QUALIFIERS,
)
from agent_bom.core.versions.maven import (
    _compare_maven_versions as _compare_maven_versions,
)
from agent_bom.core.versions.maven import (
    _maven_compare_items as _maven_compare_items,
)
from agent_bom.core.versions.maven import (
    _maven_item_rank as _maven_item_rank,
)
from agent_bom.core.versions.maven import (
    _maven_parse as _maven_parse,
)
from agent_bom.core.versions.maven import (
    _maven_qualifier_key as _maven_qualifier_key,
)
from agent_bom.core.versions.maven import (
    _MavenInt as _MavenInt,
)
from agent_bom.core.versions.maven import (
    _MavenList as _MavenList,
)
from agent_bom.core.versions.maven import (
    _MavenStr as _MavenStr,
)
from agent_bom.core.versions.nuget import (
    _NUGET_VERSION_RE as _NUGET_VERSION_RE,
)
from agent_bom.core.versions.nuget import (
    _compare_nuget_label as _compare_nuget_label,
)
from agent_bom.core.versions.nuget import (
    _compare_nuget_labels as _compare_nuget_labels,
)
from agent_bom.core.versions.nuget import (
    _compare_nuget_versions as _compare_nuget_versions,
)
from agent_bom.core.versions.nuget import (
    _parse_nuget_version as _parse_nuget_version,
)
from agent_bom.core.versions.ordering import (
    _NUGET_ECOSYSTEMS as _NUGET_ECOSYSTEMS,
)
from agent_bom.core.versions.ordering import (
    _PACKAGIST_ECOSYSTEMS as _PACKAGIST_ECOSYSTEMS,
)
from agent_bom.core.versions.ordering import (
    _RUBYGEMS_ECOSYSTEMS as _RUBYGEMS_ECOSYSTEMS,
)
from agent_bom.core.versions.ordering import (
    _SEMVER_PRERELEASE_TAGS as _SEMVER_PRERELEASE_TAGS,
)
from agent_bom.core.versions.ordering import (
    _STRICT_SEMVER as _STRICT_SEMVER,
)
from agent_bom.core.versions.ordering import (
    _compare_strict_semver as _compare_strict_semver,
)
from agent_bom.core.versions.ordering import (
    _compare_with_local_suffix_strip as _compare_with_local_suffix_strip,
)
from agent_bom.core.versions.ordering import (
    _pep440_version as _pep440_version,
)
from agent_bom.core.versions.ordering import (
    _split_local_style_suffix as _split_local_style_suffix,
)
from agent_bom.core.versions.ordering import (
    _strip_semver_prerelease_tag as _strip_semver_prerelease_tag,
)
from agent_bom.core.versions.ordering import (
    compare_version_order as compare_version_order,
)
from agent_bom.core.versions.ordering import (
    compare_versions as compare_versions,
)
from agent_bom.core.versions.php import (
    _PHP_PART_ORDER as _PHP_PART_ORDER,
)
from agent_bom.core.versions.php import (
    _PHP_UNLISTED_PART as _PHP_UNLISTED_PART,
)
from agent_bom.core.versions.php import (
    _compare_php_versions as _compare_php_versions,
)
from agent_bom.core.versions.php import (
    _php_canonicalize_version as _php_canonicalize_version,
)
from agent_bom.core.versions.php import (
    _php_compare_parts as _php_compare_parts,
)
from agent_bom.core.versions.php import (
    _php_compare_slices as _php_compare_slices,
)
from agent_bom.core.versions.ranges import (
    _resolve_version_range as _resolve_version_range,
)
from agent_bom.core.versions.ranges import (
    normalize_introduced as normalize_introduced,
)
from agent_bom.core.versions.ruby import (
    _GEM_SEGMENT_RE as _GEM_SEGMENT_RE,
)
from agent_bom.core.versions.ruby import (
    _GEM_VERSION_RE as _GEM_VERSION_RE,
)
from agent_bom.core.versions.ruby import (
    _compare_gem_versions as _compare_gem_versions,
)
from agent_bom.core.versions.ruby import (
    _gem_canonical_segments as _gem_canonical_segments,
)
from agent_bom.core.versions.validation import (
    _GO_PSEUDO_RE as _GO_PSEUDO_RE,
)
from agent_bom.core.versions.validation import (
    _GO_VERSION_RE as _GO_VERSION_RE,
)
from agent_bom.core.versions.validation import (
    _HEXISH_RE as _HEXISH_RE,
)
from agent_bom.core.versions.validation import (
    _MAVEN_RE as _MAVEN_RE,
)
from agent_bom.core.versions.validation import (
    _PEP440_RE as _PEP440_RE,
)
from agent_bom.core.versions.validation import (
    _SEMVER_RE as _SEMVER_RE,
)
from agent_bom.core.versions.validation import (
    _looks_like_commit_sha as _looks_like_commit_sha,
)
from agent_bom.core.versions.validation import (
    is_prerelease_version as is_prerelease_version,
)
from agent_bom.core.versions.validation import (
    normalize_version as normalize_version,
)
from agent_bom.core.versions.validation import (
    strip_pip_extras as strip_pip_extras,
)
from agent_bom.core.versions.validation import (
    validate_version as validate_version,
)
from agent_bom.http_client import request_with_retry

_logger = logging.getLogger(__name__)


def _dropped_bound_message(bound: str, ecosystem: str) -> str:
    return (
        f"advisory version bound {bound!r} ({ecosystem}) could not be compared; the affected range was dropped, so results may under-report"
    )


@lru_cache(maxsize=4096)
def _log_unparseable_bound(bound: str, ecosystem: str) -> None:
    """Log (once per distinct bound) that a range comparison was dropped.

    Either side of the comparison can be at fault — the bound itself, or an
    installed/candidate version the ecosystem's ordering cannot place (a git
    SHA leaking out of a ``GIT`` range, say) — so the wording blames neither.
    """
    _logger.warning(
        "Advisory version bound %r (%s) could not be compared; failing closed — the bound "
        "cannot establish a match, so affected-range accuracy may be reduced",
        bound,
        ecosystem,
    )


def _warn_unparseable_bound(bound: str, ecosystem: str) -> None:
    """Report a dropped advisory bound to the log AND to ``scan_warnings``.

    Failing closed on a bound we cannot compare is the right policy; dropping
    the EVIDENCE of it is not. A log line reaches nobody downstream — the JSON
    and SARIF payloads, the console summary and the exit code all saw a result
    indistinguishable from a genuinely clean one.

    The log side stays memoised so a corpus-wide sweep does not print the same
    line thousands of times, but the scan-warning side must fire on EVERY scan:
    ``record_scan_warning`` already dedupes within one scan's boundary, and a
    second scan in the same process has its own boundary.
    """
    _log_unparseable_bound(bound, ecosystem)
    from agent_bom.scanners.state import record_scan_warning

    record_scan_warning(_dropped_bound_message(bound, ecosystem))


def version_in_range(
    version: str,
    introduced: str | None,
    fixed: str | None,
    last_affected: str | None,
    ecosystem: str,
) -> bool:
    """Return whether ``version`` is affected by the supplied advisory bounds.

    The decision itself is memoised; the reporting of any bound it had to drop
    is not, so a cache hit can never swallow the warning.
    """
    affected, dropped = _resolve_version_range(version, introduced, fixed, last_affected, ecosystem)
    for bound in dropped:
        _warn_unparseable_bound(bound, ecosystem)
    return affected


async def resolve_go_metadata(
    module: str,
    client: object,
) -> tuple[str | None, str | None]:
    """Resolve latest Go module version via proxy.golang.org.

    Returns (version, None) — Go proxy doesn't provide license info.
    """

    # Go proxy requires case-encoded module paths (upper → !lower)
    # and forward slashes are kept as literal path separators.
    encoded = _go_encode_module(module)
    url = f"https://proxy.golang.org/{encoded}/@latest"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            version = data.get("Version")
            return version, None
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_cargo_metadata(
    crate_name: str,
    client: object,
) -> tuple[str | None, str | None]:
    """Resolve latest Cargo crate version and license via crates.io.

    Returns (version, license).
    """

    url = f"https://crates.io/api/v1/crates/{_url_quote(crate_name, safe='')}"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            crate = data.get("crate", {})
            version = crate.get("newest_version") or crate.get("max_version")
            license_id = crate.get("license")
            return version, license_id
        except (ValueError, KeyError):
            pass
    return None, None


async def resolve_maven_metadata(
    group_id: str,
    artifact_id: str,
    client: object,
) -> tuple[str | None, None]:
    """Resolve latest Maven artifact version via Maven Central search API.

    Returns (version, None).
    """

    g = _url_quote(group_id, safe="")
    a = _url_quote(artifact_id, safe="")
    url = f"https://search.maven.org/solrsearch/select?q=g:{g}+AND+a:{a}&rows=1&wt=json"
    response = await request_with_retry(client, "GET", url)  # type: ignore[arg-type]
    if response and response.status_code == 200:
        try:
            data = response.json()
            docs = data.get("response", {}).get("docs", [])
            if docs:
                return docs[0].get("latestVersion"), None
        except (ValueError, KeyError):
            pass
    return None, None
