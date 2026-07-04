"""Reference-table normalization for hub finding payloads (#3513).

Repeated CVE/CVSS/EPSS enrichment and framework tag maps are stored once per
tenant in reference tables. Finding ledger rows keep join keys
(``intel_ref``, ``framework_ref``) plus sort/filter scalars.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from agent_bom.canonical_ids import canonical_id

# Enrichment blobs keyed by CVE id (tenant-scoped table).
_CVE_INTEL_KEYS: tuple[str, ...] = (
    "summary",
    "references",
    "advisory_sources",
    "primary_advisory_source",
    "cvss_vector",
    "cvss_v3_vector",
    "cvss_v4_vector",
    "epss_percentile",
    "cisa_kev",
    "is_kev",
    "kev_date",
    "kev_added_date",
    "nvd_url",
    "ghsa_id",
    "osv_id",
    "ghsa_severity",
    "nvd_published",
)

# Framework tag arrays stored once per unique tag bundle.
_FRAMEWORK_TAG_KEYS: tuple[str, ...] = (
    "owasp_tags",
    "atlas_tags",
    "nist_ai_rmf_tags",
    "owasp_mcp_tags",
    "owasp_agentic_tags",
    "eu_ai_act_tags",
    "nist_csf_tags",
    "iso_27001_tags",
    "soc2_tags",
    "cis_tags",
    "cmmc_tags",
    "compliance_tags",
    "applicable_frameworks",
)

_REF_MARKER_KEYS = ("intel_ref", "framework_ref")


def resolve_cve_id(payload: Mapping[str, Any]) -> str:
    for key in ("cve_id", "vulnerability_id", "id"):
        raw = payload.get(key)
        if raw and str(raw).upper().startswith("CVE-"):
            return str(raw).upper()
    return ""


def framework_ref_key(payload: Mapping[str, Any]) -> str:
    bundle: dict[str, Any] = {}
    for key in _FRAMEWORK_TAG_KEYS:
        value = payload.get(key)
        if value:
            bundle[key] = value
    if not bundle:
        return ""
    fingerprint = json.dumps(bundle, sort_keys=True, separators=(",", ":"), default=str)
    return canonical_id("hub_framework_ref", fingerprint)


def extract_reference_blobs(payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None, dict[str, Any] | None]:
    """Split a finding payload into a slim row plus optional reference blobs."""
    slim = dict(payload)
    cve_id = resolve_cve_id(payload)
    intel_blob: dict[str, Any] | None = None
    if cve_id:
        intel_blob = {}
        for key in _CVE_INTEL_KEYS:
            if key in slim:
                intel_blob[key] = slim.pop(key)
        if not intel_blob:
            intel_blob = None
        else:
            slim["intel_ref"] = cve_id

    framework_blob: dict[str, Any] | None = None
    fw_ref = framework_ref_key(payload)
    if fw_ref:
        framework_blob = {}
        for key in _FRAMEWORK_TAG_KEYS:
            if key in slim:
                framework_blob[key] = slim.pop(key)
        if framework_blob:
            slim["framework_ref"] = fw_ref
        else:
            framework_blob = None
            fw_ref = ""

    return slim, intel_blob, framework_blob


def is_reference_backed_payload(payload: Mapping[str, Any]) -> bool:
    return any(payload.get(key) for key in _REF_MARKER_KEYS)


def hydrate_reference_payload(
    payload: Mapping[str, Any],
    *,
    cve_intel: Mapping[str, dict[str, Any]],
    framework_refs: Mapping[str, dict[str, Any]],
) -> dict[str, Any]:
    """Merge reference blobs back into a stored finding payload."""
    if not is_reference_backed_payload(payload):
        return dict(payload)

    merged = dict(payload)
    intel_ref = str(merged.pop("intel_ref", "") or "")
    if intel_ref:
        blob = cve_intel.get(intel_ref)
        if blob:
            for key, value in blob.items():
                merged.setdefault(key, value)

    framework_ref = str(merged.pop("framework_ref", "") or "")
    if framework_ref:
        blob = framework_refs.get(framework_ref)
        if blob:
            for key, value in blob.items():
                merged.setdefault(key, value)

    return merged


def batch_reference_keys(payloads: Iterable[Mapping[str, Any]]) -> tuple[set[str], set[str]]:
    cve_ids: set[str] = set()
    framework_refs: set[str] = set()
    for payload in payloads:
        intel_ref = str(payload.get("intel_ref") or "")
        if intel_ref:
            cve_ids.add(intel_ref)
        framework_ref = str(payload.get("framework_ref") or "")
        if framework_ref:
            framework_refs.add(framework_ref)
    return cve_ids, framework_refs
