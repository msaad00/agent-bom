"""Intel GPU / oneAPI security advisory enrichment.

Cross-references Intel GPU-related packages against a static seed of known Intel CVEs.
Sources:
  Intel PSIRT: https://www.intel.com/content/www/us/en/security-center/default.html
  Intel Graphics driver security advisories
"""

from __future__ import annotations

import logging

from agent_bom.models import Package, Severity, Vulnerability

logger = logging.getLogger(__name__)

_INTEL_PRODUCT_MAP: dict[str, list[str]] = {
    "intel gpu": [
        "intel_extension_for_pytorch",
        "intel_extension_for_tensorflow",
        "openvino",
        "openvino_dev",
        "intel_npu_acceleration_library",
    ],
    "oneapi": [
        "intel_oneapi_tbb",
        "intel_oneapi_mkl",
        "intel_oneapi_dnnl",
        "dpcpp_cpp_compiler",
    ],
    "level zero": [
        "level_zero",
        "level_zero_devel",
    ],
    "igc": [
        "intel_graphics_compiler",
        "igc_core",
    ],
}

# Reverse map: normalised package name → Intel product names it belongs to
_PYPI_TO_INTEL: dict[str, list[str]] = {}
for _product, _packages in _INTEL_PRODUCT_MAP.items():
    for _pkg in _packages:
        _PYPI_TO_INTEL.setdefault(_pkg.lower().replace("-", "_"), []).append(_product)


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_")


def get_intel_products_for_package(pkg_name: str) -> list[str]:
    """Return Intel product names that a package name maps to."""
    return _PYPI_TO_INTEL.get(_normalise(pkg_name), [])


# Static advisory seed — known Intel CVEs affecting GPU/oneAPI packages.
# Each entry: (cve_id, summary, severity, cvss_score, affected_products, fixed_version, references)
_INTEL_ADVISORY_SEED: list[tuple[str, str, Severity, float | None, list[str], str | None, list[str]]] = [
    (
        "CVE-2023-22655",
        "Intel Graphics driver protection mechanism failure allows unprivileged process to escalate privilege via local access.",
        Severity.HIGH,
        7.9,
        ["intel gpu", "level zero"],
        None,
        ["https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00879.html"],
    ),
    (
        "CVE-2023-28410",
        "Improper input validation in some Intel Graphics drivers may allow an authenticated user to potentially enable denial of service.",
        Severity.MEDIUM,
        6.5,
        ["intel gpu"],
        None,
        ["https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00886.html"],
    ),
    (
        "CVE-2023-25546",
        "Out-of-bounds write in Intel Graphics drivers may allow unauthenticated users "
        "to potentially enable denial of service via local access.",
        Severity.HIGH,
        7.5,
        ["intel gpu"],
        None,
        ["https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00886.html"],
    ),
    (
        "CVE-2023-29494",
        "Improper input validation in the Intel Graphics driver kernel extension "
        "may allow a privileged user to enable escalation of privilege.",
        Severity.HIGH,
        7.8,
        ["intel gpu", "igc"],
        None,
        ["https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00879.html"],
    ),
    (
        "CVE-2024-21831",
        "Path traversal in some Intel oneAPI Toolkit software may allow an authenticated user "
        "to potentially enable escalation of privilege via local access.",
        Severity.HIGH,
        7.8,
        ["oneapi"],
        None,
        ["https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01071.html"],
    ),
]


def _build_intel_vuln(
    cve_id: str,
    summary: str,
    severity: Severity,
    cvss_score: float | None,
    fixed_version: str | None,
    references: list[str],
) -> Vulnerability:
    return Vulnerability(
        id=cve_id,
        summary=summary,
        severity=severity,
        cvss_score=cvss_score,
        fixed_version=fixed_version,
        references=references,
        advisory_sources=["intel_psirt"],
    )


def check_intel_advisories(packages: list[Package]) -> int:
    """Check Intel GPU/oneAPI packages against the Intel PSIRT advisory seed.

    Returns count of new vulnerabilities attached to the given packages.
    """
    product_to_pkgs: dict[str, list[Package]] = {}
    for pkg in packages:
        for product in get_intel_products_for_package(pkg.name):
            product_to_pkgs.setdefault(product, []).append(pkg)

    if not product_to_pkgs:
        return 0

    logger.info("Intel advisory check for products: %s", set(product_to_pkgs))

    total_new = 0
    for cve_id, summary, severity, cvss_score, affected_products, fixed_version, references in _INTEL_ADVISORY_SEED:
        vuln = _build_intel_vuln(cve_id, summary, severity, cvss_score, fixed_version, references)

        for product in affected_products:
            pkgs = product_to_pkgs.get(product, [])
            for pkg in pkgs:
                existing_ids = {v.id for v in pkg.vulnerabilities}
                for v in pkg.vulnerabilities:
                    existing_ids.update(v.aliases)
                if cve_id in existing_ids:
                    continue

                if fixed_version and pkg.version:
                    from agent_bom.version_utils import compare_versions

                    if not compare_versions(pkg.version, fixed_version, pkg.ecosystem):
                        continue

                pkg.vulnerabilities.append(vuln)
                existing_ids.add(cve_id)
                total_new += 1

    if total_new:
        logger.info("Intel advisories: found %d new CVE(s)", total_new)

    return total_new
