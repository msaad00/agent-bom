"""Hardware firmware / BMC advisory scanner for GPU accelerators.

Cross-references GPU hardware models discovered on K8s nodes against a curated
seed of BMC / SBIOS / firmware CVEs for H100, A100, and ConnectX network
adapters.  These vulnerabilities live in the **hardware management plane** —
below the OS and above the physical silicon — and are distinct from GPU driver
CVEs.

Sources:
  NVIDIA Product Security: https://www.nvidia.com/en-us/security/
  Intel Product Security: https://www.intel.com/content/www/us/en/security-center/default.html

Relates to: gpu_infra.GpuNode discovery via K8s labels.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ─── Firmware product → GPU hardware model keywords ──────────────────────────
# Used to match firmware advisories to K8s GPU node labels.
# Keys are firmware component names; values are substrings to look for in
# GPU model labels (case-insensitive).

_FIRMWARE_PRODUCT_GPU_KEYWORDS: dict[str, list[str]] = {
    "DGX H100": ["h100"],
    "HGX H100": ["h100"],
    "DGX A100": ["a100"],
    "HGX A100": ["a100"],
    "DGX Station A100": ["a100"],
    "DGX A800": ["a800"],
    "DGX H200": ["h200"],
    "HGX H200": ["h200"],
    "ConnectX-6": ["connectx", "cx6"],
    "ConnectX-7": ["connectx", "cx7"],
}

# GPU model keyword → set of relevant firmware products
# Built at module load time from the inverse of the above.
_GPU_KEYWORD_TO_PRODUCTS: dict[str, set[str]] = {}
for _prod, _keywords in _FIRMWARE_PRODUCT_GPU_KEYWORDS.items():
    for _kw in _keywords:
        _GPU_KEYWORD_TO_PRODUCTS.setdefault(_kw, set()).add(_prod)


# ─── Firmware advisory seed ───────────────────────────────────────────────────
# Each entry: (cve_id, title, severity, cvss_score, affected_products, fixed_version, reference_url)
# Severity values: "critical", "high", "medium"

FirmwareSeed = tuple[str, str, str, float, list[str], str | None, str]

_FIRMWARE_ADVISORY_SEED: list[FirmwareSeed] = [
    (
        "CVE-2023-31028",
        "NVIDIA DGX H100 BMC host-interface unauthenticated privileged operation execution",
        "critical",
        9.0,
        ["DGX H100", "HGX H100"],
        "1.05.0",
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5481",
    ),
    (
        "CVE-2023-31029",
        "NVIDIA DGX H100 BMC IPMI handler stack memory corruption via unauthenticated access",
        "critical",
        9.0,
        ["DGX H100", "HGX H100"],
        "1.05.0",
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5481",
    ),
    (
        "CVE-2023-31030",
        "NVIDIA DGX H100 BMC CLI command injection allows privileged attacker escalation",
        "high",
        7.2,
        ["DGX H100"],
        "1.05.0",
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5481",
    ),
    (
        "CVE-2023-25513",
        "NVIDIA DGX A100 SBIOS pre-boot environment local privilege escalation and info disclosure",
        "high",
        7.5,
        ["DGX A100", "HGX A100", "DGX Station A100"],
        "1.21.1",
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5456",
    ),
    (
        "CVE-2023-25519",
        "NVIDIA ConnectX-6 Dx/Lx firmware authenticated denial of service via network-adjacent access",
        "high",
        7.1,
        ["ConnectX-6"],
        None,
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5456",
    ),
    (
        "CVE-2024-0090",
        "NVIDIA DGX Station A100 firmware out-of-bounds write allows local code execution and data tampering",
        "high",
        7.8,
        ["DGX Station A100"],
        "6.1.0",
        "https://nvidia.custhelp.com/app/answers/detail/a_id/5551",
    ),
]


# ─── Result dataclass ─────────────────────────────────────────────────────────


@dataclass
class FirmwareFinding:
    """A single firmware/BMC CVE finding for a GPU node."""

    node_name: str
    gpu_vendor: str
    gpu_model: str  # model string extracted from labels
    cve_id: str
    title: str
    severity: str
    cvss_score: float
    affected_product: str  # which firmware product matched
    fixed_version: str | None
    reference_url: str

    def to_dict(self) -> dict:
        return {
            "node": self.node_name,
            "gpu_vendor": self.gpu_vendor,
            "gpu_model": self.gpu_model,
            "cve_id": self.cve_id,
            "title": self.title,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "affected_product": self.affected_product,
            "fixed_version": self.fixed_version,
            "reference_url": self.reference_url,
        }


# ─── GPU model extraction ─────────────────────────────────────────────────────

# Label keys that carry GPU model/product information (checked in order)
_GPU_MODEL_LABEL_KEYS: tuple[str, ...] = (
    "nvidia.com/gpu.product",
    "nvidia.com/gpu.model",
    "beta.kubernetes.io/instance-type",
    "node.kubernetes.io/instance-type",
)

_GPU_MODEL_RE = re.compile(
    r"\b(H200|H100|A800|A100|A40|A30|A10|V100|T4|L40|L4|RTX\s*\d{4}|"
    r"MI300X|MI250X|MI210|MI100|RX\s*\d{4}|"
    r"ConnectX-\d|CX\d)\b",
    re.IGNORECASE,
)


def extract_gpu_model_from_labels(labels: dict[str, str]) -> str:
    """Extract a GPU model identifier from a K8s node's labels.

    Returns a normalised uppercase model string (e.g. ``"H100"``) or empty string.
    """
    for key in _GPU_MODEL_LABEL_KEYS:
        value = labels.get(key, "")
        if not value:
            continue
        m = _GPU_MODEL_RE.search(value)
        if m:
            return m.group(0).upper().replace(" ", "")
    return ""


def _products_for_model(gpu_model: str) -> set[str]:
    """Return firmware product names relevant to a GPU model string."""
    model_lower = gpu_model.lower()
    matched: set[str] = set()
    for keyword, products in _GPU_KEYWORD_TO_PRODUCTS.items():
        if keyword in model_lower:
            matched |= products
    return matched


# ─── Main check ──────────────────────────────────────────────────────────────


def check_firmware_advisories(nodes: list) -> list[FirmwareFinding]:
    """Check a list of :class:`~agent_bom.cloud.gpu_infra.GpuNode` objects
    against the firmware advisory seed.

    Matches are based on GPU model keywords extracted from K8s node labels.
    Returns a list of :class:`FirmwareFinding` — one per (node, CVE) pair.
    """
    findings: list[FirmwareFinding] = []

    for node in nodes:
        gpu_model = extract_gpu_model_from_labels(getattr(node, "labels", {}))
        if not gpu_model:
            # Fallback: derive model from vendor label values
            for v in (getattr(node, "labels", {}) or {}).values():
                m = _GPU_MODEL_RE.search(v)
                if m:
                    gpu_model = m.group(0).upper().replace(" ", "")
                    break

        if not gpu_model:
            continue

        relevant_products = _products_for_model(gpu_model)
        if not relevant_products:
            continue

        node_name = getattr(node, "name", "")
        gpu_vendor = getattr(node, "gpu_vendor", "unknown")

        seen_cves: set[str] = set()
        for cve_id, title, severity, cvss_score, affected_products, fixed_version, ref_url in _FIRMWARE_ADVISORY_SEED:
            if cve_id in seen_cves:
                continue
            for product in affected_products:
                if product in relevant_products:
                    seen_cves.add(cve_id)
                    findings.append(
                        FirmwareFinding(
                            node_name=node_name,
                            gpu_vendor=gpu_vendor,
                            gpu_model=gpu_model,
                            cve_id=cve_id,
                            title=title,
                            severity=severity,
                            cvss_score=cvss_score,
                            affected_product=product,
                            fixed_version=fixed_version,
                            reference_url=ref_url,
                        )
                    )
                    break

        if findings:
            logger.info(
                "firmware_advisory: node %s (%s) matched %d firmware CVE(s)",
                node_name,
                gpu_model,
                sum(1 for f in findings if f.node_name == node_name),
            )

    return findings
