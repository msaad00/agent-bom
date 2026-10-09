"""Bounded OSV Git-tag lookups for installed CPython runtimes.

The result describes the upstream release's advisories, not exploitability or
an exhaustive assessment of downstream modifications to that release.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

from agent_bom import http_client
from agent_bom.models import Package, Vulnerability
from agent_bom.package_utils import canonical_package_key
from agent_bom.scanners.state import record_coverage_warning
from agent_bom.security import SecurityError
from agent_bom.version_utils import compare_version_order
from agent_bom.vuln_compliance import tag_vulnerability

REPOSITORY = "https://github.com/python/cpython"
QUERY_URL = "https://api.osv.dev/v1/query"
_VERSION = re.compile(r"3\.[0-9]{1,2}\.[0-9]{1,3}")
_MAX_PAGES = 8
# Exact upstream source from the CPython 3.14 security backport. This is a
# measured file match, not a caller-provided VEX statement or version override.
_TARFILE_FIX = "82ac045a2d97396a295405268a5f14393620b0ebf50e9305e56f34731e1d89ea"
_TARFILE_COMMIT = "https://github.com/python/cpython/commit/a4919937a4e1e69a0d178909c6f20557eca5d1d0"


def is_cpython_runtime(package: Package) -> bool:
    return getattr(package, "ecosystem", None) == "generic" and getattr(package, "name", None) == "cpython"


def runtime_assessment_key(package: Package) -> str:
    """Keep patched and unpatched instances separate during scan deduplication."""
    if not is_cpython_runtime(package):
        return ""
    measured = {
        "source_hashes": getattr(package, "_cpython_source_hashes", {}),
        "version_source": package.version_source,
        "installed_paths": sorted(
            str(item.get("source_file", "")) for item in package.version_evidence if item.get("type") == "installed_metadata"
        ),
    }
    return hashlib.sha256(json.dumps(measured, sort_keys=True).encode()).hexdigest()


def advisory_instance_key(package: Package) -> str:
    """Join ordinary identities while separating independently measured runtimes."""
    key = canonical_package_key(package.name, package.version, package.ecosystem, package.purl)
    runtime_key = runtime_assessment_key(package)
    return f"{key}:runtime-source:{runtime_key}" if runtime_key else key


async def _lookup(package: Package) -> list[dict[str, Any]]:
    version = package.version
    if not _VERSION.fullmatch(version):
        raise ValueError("Unverified CPython release identity")
    expected_path = f"usr/local/include/python{'.'.join(version.split('.')[:2])}/patchlevel.h"
    if package.version_source != "installed_package" or not any(
        item.get("type") == "installed_metadata" and str(item.get("source_file", "")).removeprefix("./") == expected_path
        for item in package.version_evidence
    ):
        raise ValueError("Missing installed CPython identity evidence")

    tag = f"v{version}"
    # A successful empty OSV response alone cannot distinguish an unknown tag
    # from a release with no matching advisories. Verify the release first.
    async with http_client.create_client(timeout=20.0) as client:
        response = await http_client.request_with_retry(
            client, "GET", f"https://raw.githubusercontent.com/python/cpython/{tag}/Include/patchlevel.h"
        )
        if response is None or response.status_code != 200 or len(response.content) > 65_536:
            raise ValueError("CPython release verification unavailable")
        match = re.search(rb'^\s*#\s*define\s+PY_VERSION\s+"([^"]+)"', response.content, re.MULTILINE)
        if match is None or match[1].decode("ascii") != version:
            raise ValueError("CPython release identity mismatch")

        payload: dict[str, Any] = {"package": {"name": REPOSITORY, "ecosystem": "GIT"}, "version": tag}
        seen_tokens: set[str] = set()
        advisories: dict[str, dict[str, Any]] = {}
        for _ in range(_MAX_PAGES):
            response = await http_client.request_with_retry(client, "POST", QUERY_URL, json=payload)
            if response is None or response.status_code != 200 or len(response.content) > 4_000_000:
                raise ValueError("Runtime advisory lookup unavailable")
            data = response.json()
            if not isinstance(data, dict) or set(data) - {"vulns", "next_page_token"} or not isinstance(data.get("vulns", []), list):
                raise ValueError("Malformed runtime advisory response")
            for advisory in data.get("vulns", []):
                if not isinstance(advisory, dict) or not isinstance(advisory.get("id"), str) or not advisory["id"]:
                    raise ValueError("Missing runtime advisory identity")
                if advisory.get("withdrawn"):
                    continue
                affected = advisory.get("affected")
                if not isinstance(affected, list) or not any(
                    isinstance(entry, dict)
                    and tag in entry.get("versions", [])
                    and any(
                        isinstance(rng, dict) and rng.get("type") == "GIT" and rng.get("repo") == REPOSITORY
                        for rng in entry.get("ranges", [])
                    )
                    for entry in affected
                ):
                    raise ValueError("Runtime advisory lacks verified repository and release scope")
                advisories[advisory["id"]] = advisory
                if len(advisories) > 1_000:
                    raise ValueError("Runtime advisory result limit reached")
            token = data.get("next_page_token")
            if token is None:
                return list(advisories.values())
            if not isinstance(token, str) or not token or token in seen_tokens:
                raise ValueError("Invalid runtime advisory continuation")
            seen_tokens.add(token)
            payload["page_token"] = token
    raise ValueError("Runtime advisory page limit reached")


def _release_fix(advisory: dict[str, Any], version: str) -> str | None:
    """Fixed release from the window that contains ``version``, if published.

    The GIT range's ``fixed`` events are commit SHAs; OSV records the
    release-numbered windows in ``database_specific.extracted_events``. Only a
    window containing the installed release yields a fix, so no cross-branch
    upgrade is advised.
    """
    for affected in advisory.get("affected") or []:
        for rng in affected.get("ranges") or [] if isinstance(affected, dict) else []:
            if not isinstance(rng, dict) or rng.get("type") != "GIT" or rng.get("repo") != REPOSITORY:
                continue
            events = (rng.get("database_specific") or {}).get("extracted_events")
            introduced: str | None = None
            for event in events if isinstance(events, list) else []:
                if not isinstance(event, dict):
                    continue
                if isinstance(event.get("introduced"), str):
                    introduced = event["introduced"]
                    continue
                fixed = event.get("fixed")
                if introduced is None or not isinstance(fixed, str):
                    continue
                lower = compare_version_order(introduced, version, "pypi") if introduced != "0" else -1
                upper = compare_version_order(version, fixed, "pypi")
                if lower is not None and upper is not None and lower <= 0 and upper < 0:
                    return fixed
                introduced = None
    return None


def _attach_release_fixes(findings: list[Vulnerability], advisories: list[dict[str, Any]], version: str) -> None:
    fixes: dict[str, str] = {}
    for advisory in advisories:
        fix = _release_fix(advisory, version)
        if fix:
            fixes.update({key: fix for key in [advisory.get("id"), *(advisory.get("aliases") or [])] if isinstance(key, str)})
    for finding in findings:
        if finding.fixed_version is None:
            finding.fixed_version = next((fixes[key] for key in [finding.id, *finding.aliases] if key in fixes), None)


async def scan_cpython_runtimes(packages: list[Package], *, offline: bool) -> int:
    """Attach version-scoped findings; failures remain explicit coverage gaps."""
    from agent_bom.scanners.package_scan import build_vulnerabilities, merge_scanner_vulnerabilities

    total = 0
    for package in packages:
        package.version_evidence = [
            item for item in package.version_evidence if item.get("type") not in {"runtime_advisory_lookup", "runtime_advisory_fix"}
        ]
        try:
            if offline:
                raise ValueError("Runtime advisory lookup requires online evidence")
            advisories = await _lookup(package)
            findings = build_vulnerabilities(advisories, package)
            _attach_release_fixes(findings, advisories, package.version)
        except (ValueError, TypeError, KeyError, AttributeError, httpx.HTTPError, http_client.OfflineModeError, SecurityError):
            record_coverage_warning(
                {
                    "ecosystem": "generic",
                    "release": f"cpython:{package.version}",
                    "reason": "runtime_advisory_coverage_unknown",
                    "package_count": 1,
                    "advisory_rows": 0,
                    "detail": (
                        "CPython runtime advisory coverage is unknown: "
                        "release identity or a complete online OSV lookup could not be verified."
                    ),
                }
            )
            continue
        active_findings = []
        fixed_ids = set()
        for finding in findings:
            path = "usr/local/lib/python3.14/tarfile.py"
            if (
                package.version == "3.14.8"
                and finding.id == "CVE-2026-87910"
                and getattr(package, "_cpython_source_hashes", {}).get(path) == _TARFILE_FIX
            ):
                package.version_evidence.append(
                    {
                        "type": "runtime_advisory_fix",
                        "advisory_id": finding.id,
                        "status": "fixed_source_observed",
                        "source_file": path,
                        "sha256": _TARFILE_FIX,
                        "upstream_fix": _TARFILE_COMMIT,
                        "boundary": "Exact installed module source matches the upstream fix; this is not runtime attestation.",
                    }
                )
                fixed_ids.add(finding.id)
                continue
            finding.compliance_tags = tag_vulnerability(finding, package)
            active_findings.append(finding)
        package.vulnerabilities = [finding for finding in package.vulnerabilities if finding.id not in fixed_ids]
        total += len(merge_scanner_vulnerabilities(package, active_findings))
        package.version_evidence.append(
            {
                "type": "runtime_advisory_lookup",
                "url": QUERY_URL,
                "repository_url": REPOSITORY,
                "tag": f"v{package.version}",
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "advisory_count": len(advisories),
                "assessment": "upstream_release_lookup_complete",
            }
        )
    return total


def propagate_runtime_assessments(packages: list[Package], scanned: list[Package]) -> None:
    """Carry current lookup receipts to independently inventoried duplicates."""
    assessed = {advisory_instance_key(package): package for package in scanned if is_cpython_runtime(package)}
    receipt_types = {"runtime_advisory_lookup", "runtime_advisory_fix"}
    for package in packages:
        if not is_cpython_runtime(package):
            continue
        source = assessed.get(advisory_instance_key(package))
        if source is None or source is package:
            continue
        receipts = [dict(item) for item in source.version_evidence if item.get("type") in receipt_types]
        package.version_evidence = [item for item in package.version_evidence if item.get("type") not in receipt_types] + receipts
        if any(item.get("type") == "runtime_advisory_lookup" for item in receipts):
            package.vulnerabilities = list(source.vulnerabilities)
