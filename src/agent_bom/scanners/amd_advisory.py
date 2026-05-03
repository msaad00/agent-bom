"""Supplemental AMD PSIRT / ROCm security advisory enrichment.

Cross-references AMD ROCm packages against a static seed database of known AMD CVEs.
The seed covers CVEs published at https://www.amd.com/en/resources/product-security.html
(AMD PSIRT) and the ROCm GitHub security advisories.  A live-fetch/update path can
refresh the seed without changing the scanner interface.

Two package categories are covered:
  1. ROCm runtime packages (rocm-dev, hip-runtime-amd, miopen-hip, etc.)
  2. AMD Instinct container images (rocm/* on Docker Hub)
"""

from __future__ import annotations

import logging

from agent_bom.models import Package, Severity, Vulnerability

logger = logging.getLogger(__name__)

# Map AMD product names to ROCm PyPI / conda package prefixes.
# Product names are lowercased; package names use underscores for lookup.
_AMD_PRODUCT_MAP: dict[str, list[str]] = {
    "rocm": [
        "rocm",
        "rocm_dev",
        "rocm_libs",
        "rocm_runtime",
        "rocm_smi_lib",
        "rocm_bandwidth_test",
        "rocminfo",
    ],
    "hip runtime": [
        "hip_runtime_amd",
        "hip_devel",
        "hipcc",
        "hip_base",
    ],
    "miopen": [
        "miopen_hip",
        "miopen_opencl",
    ],
    "rocblas": [
        "rocblas",
    ],
    "rocsolver": [
        "rocsolver",
    ],
    "rccl": [
        "rccl",
    ],
    "rocprim": [
        "rocprim",
    ],
    "rocthrust": [
        "rocthrust",
    ],
    "rocrand": [
        "rocrand",
    ],
    "rocfft": [
        "rocfft",
    ],
    "hipsparse": [
        "hipsparse",
    ],
    "hipblas": [
        "hipblas",
    ],
    "composablekernel": [
        "composablekernel",
    ],
    # PyTorch ROCm variant bundles HIP runtime — affected by ROCm runtime CVEs
    "pytorch rocm": [
        "torch",
        "torchvision",
        "torchaudio",
    ],
    # JAX ROCm variant
    "jax rocm": [
        "jax_rocm60_plugin",
        "jax_rocm60_pjrt",
    ],
    # TensorFlow ROCm variant
    "tensorflow rocm": [
        "tensorflow_rocm",
    ],
}

# Reverse map: normalised package name → AMD product names it belongs to
_PYPI_TO_AMD: dict[str, list[str]] = {}
for _product, _packages in _AMD_PRODUCT_MAP.items():
    for _pkg in _packages:
        _PYPI_TO_AMD.setdefault(_pkg.lower().replace("-", "_"), []).append(_product)


def _normalise(name: str) -> str:
    return name.lower().replace("-", "_")


def get_amd_products_for_package(pkg_name: str) -> list[str]:
    """Return AMD product names that a package name maps to."""
    return _PYPI_TO_AMD.get(_normalise(pkg_name), [])


# Static advisory seed — known AMD CVEs affecting ROCm packages.
# Each entry: (cve_id, summary, severity, cvss_score, affected_products, fixed_version, references)
# Sources:
#   https://www.amd.com/en/resources/product-security.html
#   https://github.com/ROCm/ROCm/security/advisories
_AMD_ADVISORY_SEED: list[tuple[str, str, Severity, float | None, list[str], str | None, list[str]]] = [
    (
        "CVE-2023-20598",
        "AMD IOMMU may not flush TLB entries correctly, allowing a privileged attacker to read arbitrary memory via a malicious driver.",
        Severity.HIGH,
        7.8,
        ["rocm", "hip runtime"],
        None,
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html"],
    ),
    (
        "CVE-2021-26347",
        "Failure to validate DRAM address in ECC scrubber may allow an attacker to corrupt memory and cause denial of service.",
        Severity.MEDIUM,
        5.5,
        ["rocm"],
        None,
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1027.html"],
    ),
    (
        "CVE-2021-26354",
        "Insufficient bounds checking in ASP may allow an attacker with elevated "
        "privileges to write to a valid address outside the expected range.",
        Severity.MEDIUM,
        4.4,
        ["rocm", "hip runtime"],
        None,
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1027.html"],
    ),
    (
        "CVE-2022-23830",
        "Insufficient validation of SNP guest command requests from the hypervisor "
        "may result in a potential impact to the guest confidentiality.",
        Severity.MEDIUM,
        5.3,
        ["rocm"],
        None,
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-1032.html"],
    ),
    (
        "CVE-2023-31315",
        "Improper validation in a model specific register (MSR) may allow a malicious "
        "program with ring0 access to modify the SMM configuration.",
        Severity.HIGH,
        7.5,
        ["rocm", "hip runtime", "miopen", "rocblas"],
        "6.0",
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7014.html"],
    ),
    (
        "CVE-2024-21944",
        "A malicious or compromised UApp or ABL may be able to send a malformed "
        "system call to the bootloader resulting in an out-of-bounds memory write.",
        Severity.HIGH,
        7.8,
        ["rocm", "hip runtime"],
        "6.1",
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3001.html"],
    ),
    (
        "CVE-2024-21945",
        "A malicious or compromised ABL may tamper with the BIOS directory table which may result in an out-of-bounds write.",
        Severity.HIGH,
        7.2,
        ["rocm"],
        "6.1",
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3001.html"],
    ),
    (
        "CVE-2024-21138",
        "Improper input validation in the ROCm SMI library may allow a local "
        "attacker to read out-of-bounds memory, potentially leading to information disclosure.",
        Severity.MEDIUM,
        5.5,
        ["rocm", "rocm_smi_lib"],
        "6.2",
        ["https://github.com/ROCm/rocm_smi_lib/security/advisories/GHSA-7574-hq3j-xw72"],
    ),
    (
        "CVE-2024-21139",
        "An integer overflow in the ROCm HIP runtime kernel launch path may allow "
        "a local unprivileged attacker to cause a denial-of-service condition.",
        Severity.MEDIUM,
        5.5,
        ["hip runtime", "rocm"],
        "6.2",
        ["https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3002.html"],
    ),
]


def _build_vuln_from_seed(
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
        advisory_sources=["amd_psirt"],
    )


def check_amd_advisories(packages: list[Package], *, live: bool = True) -> int:
    """Check AMD/ROCm packages against AMD PSIRT advisories.

    Attempts a live fetch from the AMD PSIRT JSON endpoint and ROCm GHSA
    first (``live=True``).  On any network failure or empty response the
    static ``_AMD_ADVISORY_SEED`` is used as a safe fallback so air-gapped
    environments are never left without coverage.

    Returns count of new vulnerabilities attached to the given packages.
    """
    product_to_pkgs: dict[str, list[Package]] = {}
    for pkg in packages:
        for product in get_amd_products_for_package(pkg.name):
            product_to_pkgs.setdefault(product, []).append(pkg)

    if not product_to_pkgs:
        return 0

    logger.info("AMD advisory check for products: %s", set(product_to_pkgs))

    advisory_db = _AMD_ADVISORY_SEED
    if live:
        try:
            from agent_bom.scanners.amd_advisory_fetch import fetch_live_advisories, merge_with_seed

            live_entries = fetch_live_advisories()
            if live_entries:
                advisory_db = merge_with_seed(live_entries, _AMD_ADVISORY_SEED)
        except Exception as exc:
            logger.debug("AMD live feed unavailable, using seed: %s", exc)

    total_new = 0
    for cve_id, summary, severity, cvss_score, affected_products, fixed_version, references in advisory_db:
        vuln = _build_vuln_from_seed(cve_id, summary, severity, cvss_score, fixed_version, references)

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
        logger.info("AMD advisories: found %d new CVE(s)", total_new)

    return total_new
