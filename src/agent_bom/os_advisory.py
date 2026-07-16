"""OS distro → OSV advisory ecosystem resolution and coverage reporting.

Maps a scanned OS package's distro (identified by ``/etc/os-release`` ``ID`` +
``VERSION_ID``) to the OSV advisory ecosystem key(s) its vulnerabilities live
under. The per-distro version comparison itself is handled by
:mod:`agent_bom.version_utils` (rpm EVR, dpkg, apk semantics); this module only
resolves which ecosystem key(s) to query and how to normalise the keys the OSV
bulk export stores.

The OSV all-ecosystems bulk export already carries advisories for these distro
families, so extending coverage is a matter of *routing* installed packages to
the right ecosystem key — not ingesting a new feed. Alpine (secdb) and Debian
(security-tracker) additionally have dedicated feeds handled in ``db/sync.py``.

Verified against real OSV bulk-export data (2026-07-16):

======================  ============================================================
Distro (os-release ID)  OSV ecosystem key(s)
======================  ============================================================
rhel / centos / redhat  ``Red Hat:enterprise_linux:<major>`` (bulk export stores it
                        repo/module-qualified, e.g. ``…:8::baseos`` /
                        ``…:10.0``; :func:`normalize_redhat_ecosystem` collapses
                        those to the canonical per-major key at ingest). The live
                        OSV API is queried with the bare ``Red Hat`` ecosystem,
                        which it accepts and version-filters via the ``.elN`` tag.
rocky                   ``Rocky Linux:<major>``  (e.g. ``Rocky Linux:8``)
almalinux / alma        ``AlmaLinux:<major>``    (e.g. ``AlmaLinux:9``)
opensuse-leap           ``openSUSE:Leap <ver>`` and ``openSUSE:Leap <ver> NonFree``
wolfi                   ``Wolfi``
chainguard              ``Chainguard``
======================  ============================================================

Deferred (advisory source not in the OSV export / version-compare unverified):
Amazon Linux (ALAS), Oracle Linux (ELSA), SUSE Linux Enterprise product modules,
openSUSE Tumbleweed. These need dedicated feeds and are tracked as follow-ups
rather than shipped as guessed matchers.
"""

from __future__ import annotations

import re
from collections.abc import Iterable

# ── distro os-release ID sets ────────────────────────────────────────────────
# Values are the lowercased ``/etc/os-release`` ``ID`` fields we route on.

_ROCKY_IDS = frozenset({"rocky"})
_ALMA_IDS = frozenset({"almalinux", "alma"})
# CentOS Linux is a bug-for-bug RHEL rebuild, so its packages match Red Hat
# advisories; CentOS Stream is upstream of RHEL but close enough that the Red Hat
# advisory set is the best available match (mainstream scanners do the same).
_RHEL_IDS = frozenset({"rhel", "redhat", "red hat", "centos", "scientific"})
_OPENSUSE_LEAP_IDS = frozenset({"opensuse-leap", "opensuse", "opensuse-leap-micro"})
_WOLFI_IDS = frozenset({"wolfi"})
_CHAINGUARD_IDS = frozenset({"chainguard"})

# Base ecosystem family (the part before the first ``:``, lowercased) → the
# version comparator key. Consumed by ``db.lookup._ECO_FAMILY_TO_COMPARATOR``.
OS_DISTRO_COMPARATOR_FAMILIES: dict[str, str] = {
    "red hat": "rpm",
    "rocky linux": "rpm",
    "almalinux": "rpm",
    "opensuse": "rpm",
    "suse": "rpm",
    "wolfi": "apk",
    "chainguard": "apk",
}

# Base ecosystem family → human coverage label, in display order. Includes the
# pre-existing Alpine/Debian/Ubuntu families so a single call reports the full
# active OS-advisory surface.
_BASE_TO_LABEL: tuple[tuple[str, str], ...] = (
    ("alpine", "Alpine"),
    ("debian", "Debian"),
    ("ubuntu", "Ubuntu"),
    ("red hat", "RHEL"),
    ("rocky linux", "Rocky Linux"),
    ("almalinux", "AlmaLinux"),
    ("opensuse", "openSUSE"),
    ("suse", "SUSE"),
    ("wolfi", "Wolfi"),
    ("chainguard", "Chainguard"),
)

_REDHAT_EL_RE = re.compile(r"^red hat:enterprise_linux:(\d+)(?:[.:].*)?$", re.IGNORECASE)


def _major(version: str) -> str:
    """Return the leading numeric major component of a ``VERSION_ID``."""
    return (version or "").strip().split(".", 1)[0].strip()


def _opensuse_leap_release(version: str) -> str:
    """Normalise an openSUSE Leap ``VERSION_ID`` (``15.5`` / ``15.5.1``) to ``15.5``."""
    raw = (version or "").strip()
    parts = raw.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        return f"{parts[0]}.{parts[1]}"
    return raw


def normalize_redhat_ecosystem(ecosystem: str) -> str:
    """Collapse a repo/module-qualified Red Hat OSV ecosystem to its per-major key.

    The OSV bulk export keys Red Hat advisories by product *stream*, e.g.
    ``Red Hat:enterprise_linux:8::baseos``, ``…:8::appstream`` or (RHEL 10+)
    ``Red Hat:enterprise_linux:10.0``. A scanned host cannot know which repo a
    package came from, so these are collapsed to a single canonical
    ``Red Hat:enterprise_linux:<major>`` key that a host resolver can match
    exactly. Non-``enterprise_linux`` Red Hat products (openshift, ceph, ansible,
    ``enterprise_linux_ai`` …) are returned unchanged — base-OS scans never match
    them, and rewriting them could collide unrelated advisories.
    """
    if not ecosystem:
        return ecosystem
    m = _REDHAT_EL_RE.match(ecosystem.strip())
    if not m:
        return ecosystem
    # Preserve the exported casing of the family prefix for display consistency.
    return f"Red Hat:enterprise_linux:{m.group(1)}"


def rpm_advisory_ecosystems(
    distro_name: str | None,
    distro_version: str | None,
    *,
    for_local_db: bool,
) -> list[str]:
    """Resolve OSV ecosystem key(s) for an rpm package from its distro context.

    Returns an empty list when the distro is unrecognised or its release cannot
    be determined, so the caller can fall back to its prior behaviour rather than
    matching against a wrong ecosystem.

    Args:
        distro_name: lowercased ``/etc/os-release`` ``ID`` (``rhel``/``rocky``/…).
        distro_version: ``VERSION_ID`` (``8.9`` / ``15.5``).
        for_local_db: when True, return the canonical key stored in the local DB
            (Red Hat collapsed to ``Red Hat:enterprise_linux:<major>``); when
            False, return the key the live OSV API accepts (bare ``Red Hat``).
    """
    name = (distro_name or "").strip().lower()
    major = _major(distro_version or "")

    if name in _ROCKY_IDS and major:
        return [f"Rocky Linux:{major}"]
    if name in _ALMA_IDS and major:
        return [f"AlmaLinux:{major}"]
    if name in _RHEL_IDS and major:
        if for_local_db:
            return [f"Red Hat:enterprise_linux:{major}"]
        return ["Red Hat"]
    if name in _OPENSUSE_LEAP_IDS:
        release = _opensuse_leap_release(distro_version or "")
        if release:
            return [f"openSUSE:Leap {release}", f"openSUSE:Leap {release} NonFree"]
    return []


def apk_advisory_ecosystems(distro_name: str | None) -> list[str]:
    """Resolve OSV ecosystem key(s) for an apk package's non-Alpine distros.

    Wolfi and Chainguard are apk-based, undated rolling distros whose advisories
    live under version-less ``Wolfi`` / ``Chainguard`` ecosystems. Returns an
    empty list for Alpine (handled by the caller's existing branch) or an
    unrecognised distro.
    """
    name = (distro_name or "").strip().lower()
    if name in _WOLFI_IDS:
        return ["Wolfi"]
    if name in _CHAINGUARD_IDS:
        return ["Chainguard"]
    return []


def covered_distro_labels(present_ecosystems: Iterable[str]) -> list[str]:
    """Map the ecosystem keys present in the local DB to OS-distro coverage labels.

    ``present_ecosystems`` is the set of distinct ``affected.ecosystem`` values
    (any case, release-suffixed or not). Returns the human labels for the OS
    distro families that have advisory rows, in a stable display order — the
    honest "which distros are actually covered" signal for the scan surface.
    """
    families = {str(e).split(":", 1)[0].strip().lower() for e in present_ecosystems if e}
    return [label for base, label in _BASE_TO_LABEL if base in families]


__all__ = [
    "OS_DISTRO_COMPARATOR_FAMILIES",
    "apk_advisory_ecosystems",
    "covered_distro_labels",
    "normalize_redhat_ecosystem",
    "rpm_advisory_ecosystems",
]
