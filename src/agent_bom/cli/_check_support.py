"""Package-spec parsing, verdict payloads and output writers shared by ``check``."""

from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path
from typing import Any, Optional

import click

from agent_bom import __version__
from agent_bom.core.severity import severity_at_or_above


def _response_has_version(response, ecosystem: str, version: str) -> bool:
    """Return True when a registry response contains the requested version."""
    if response is None or response.status_code != 200:
        return False
    if version in {"unknown", "", "latest"}:
        return True
    try:
        payload = response.json()
    except Exception:
        return False
    if ecosystem == "pypi":
        return version in (payload.get("releases") or {})
    return version in (payload.get("versions") or {})


def _detect_ecosystem(name: str, version: str = "unknown") -> Optional[str]:
    """Detect ecosystem by checking package and version presence on PyPI or npm."""
    try:
        from agent_bom.http_client import sync_get

        pypi_resp = sync_get(f"https://pypi.org/pypi/{name}/json", timeout=3)
        npm_resp = sync_get(f"https://registry.npmjs.org/{name}", timeout=3)
        on_pypi = _response_has_version(pypi_resp, "pypi", version)
        on_npm = _response_has_version(npm_resp, "npm", version)

        if on_pypi and not on_npm:
            return "pypi"
        if on_npm and not on_pypi:
            return "npm"
        return None
    except Exception:
        return None


def _parse_package_spec(
    package_spec: str,
    ecosystem: Optional[str] = None,
) -> tuple[str, str, str]:
    """Parse a package spec into (name, version, ecosystem).

    Handles npx/uvx prefixes, scoped npm packages, and name@version.
    Auto-detects ecosystem when not specified.
    """
    spec = package_spec.strip()
    # Accept both pip (pkg==1.0) and universal (pkg@1.0) syntax
    if "==" in spec and "@" not in spec:
        spec = spec.replace("==", "@", 1)
    if spec.startswith("npx ") or spec.startswith("uvx "):
        parts = spec.split()
        pkg_args = [p for p in parts[1:] if not p.startswith("-")]
        spec = pkg_args[0] if pkg_args else spec
        if not ecosystem:
            ecosystem = "pypi" if package_spec.startswith("uvx") else "npm"

    if "@" in spec and not spec.startswith("@"):
        name, version = spec.rsplit("@", 1)
    elif spec.startswith("@") and spec.count("@") > 1:
        last_at = spec.rindex("@")
        name, version = spec[:last_at], spec[last_at + 1 :]
    else:
        name, version = spec, "unknown"

    if not ecosystem:
        if name.startswith("@"):
            ecosystem = "npm"
        elif "." in name or "_" in name:
            ecosystem = "pypi"
        else:
            ecosystem = _detect_ecosystem(name, version) or "pypi"

    return name, version, ecosystem


def _write_json_output(payload: dict, output_path: str | None) -> None:
    """Write JSON to stdout or a file."""
    text = json.dumps(payload, indent=2)
    if output_path and output_path != "-":
        Path(output_path).write_text(text, encoding="utf-8")
        return
    click.echo(text)


def _write_sarif_output(payload: dict, output_path: str | None) -> None:
    """Write package-check SARIF to stdout or a file."""
    text = json.dumps(_check_payload_to_sarif(payload), indent=2)
    if output_path and output_path != "-":
        Path(output_path).write_text(text, encoding="utf-8")
        return
    click.echo(text)


def _check_severity_counts(vulnerabilities: list | None) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "unknown": 0}
    for vuln in vulnerabilities or []:
        if isinstance(vuln, dict):
            severity = str(vuln.get("severity") or "unknown").lower()
        else:
            severity = str(getattr(getattr(vuln, "severity", None), "value", "unknown")).lower()
        counts[severity if severity in counts else "unknown"] += 1
    return counts


def _check_agent_summary(payload: dict) -> dict:
    return {
        "agents": 0,
        "servers": None,
        "packages": 1 if payload.get("package") else 0,
        "vulnerabilities": int(payload.get("vulnerability_count") or 0),
        "findings": 0,
        "severity_counts": _check_severity_counts(payload.get("vulnerabilities")),
        "posture_grade": None,
        "verdict": payload.get("verdict"),
        "package": payload.get("package"),
        "version": payload.get("version"),
    }


def _check_agent_confidence(payload: dict) -> dict:
    vulnerabilities = payload.get("vulnerabilities") or []
    signals = [
        {"name": "package_version", "present": bool(payload.get("version") and payload.get("version") != "unknown")},
        {"name": "ecosystem", "present": bool(payload.get("ecosystems"))},
        {"name": "advisory_backing", "present": bool(vulnerabilities)},
        {"name": "external_enrichment", "present": any(bool(item.get("advisory_sources")) for item in vulnerabilities)},
    ]
    present = sum(1 for signal in signals if signal["present"])
    level = "high" if present >= 3 else "medium" if present >= 2 else "low"
    return {"level": level, "signals": signals}


def _check_sarif_properties(vuln: dict, package: str, version: str, ecosystems: list, severity: str) -> dict[str, Any]:
    """SARIF ``properties`` bag shared by a check vulnerability's rule and result."""
    cvss_score = vuln.get("cvss_score")
    properties = {
        "package": package,
        "version": version,
        "ecosystems": ecosystems,
        "severity": severity,
        "fixed_version": vuln.get("fixed_version"),
        "is_kev": bool(vuln.get("is_kev")),
        "kev_date_added": vuln.get("kev_date_added"),
        "kev_due_date": vuln.get("kev_due_date"),
        "cvss_vector": vuln.get("cvss_vector"),
        "attack_vector": vuln.get("attack_vector"),
        "attack_complexity": vuln.get("attack_complexity"),
        "privileges_required": vuln.get("privileges_required"),
        "user_interaction": vuln.get("user_interaction"),
        "network_exploitable": bool(vuln.get("network_exploitable")),
        "epss_score": vuln.get("epss_score"),
        "epss_percentile": vuln.get("epss_percentile"),
        "cwe_ids": vuln.get("cwe_ids") or [],
        "aliases": vuln.get("aliases") or [],
        "advisory_sources": vuln.get("advisory_sources") or [],
    }
    if cvss_score is not None:
        properties["security-severity"] = str(cvss_score)
    return properties


def _check_sarif_result(
    vuln: dict,
    vuln_id: str,
    severity: str,
    level: str,
    package: str,
    version: str,
    ecosystems: list,
    properties: dict[str, Any],
) -> dict[str, Any]:
    """SARIF ``result`` for one check vulnerability."""
    package_ref = f"{package}@{version}"
    fingerprint = sha256(f"check:{package}:{version}:{vuln_id}".encode("utf-8")).hexdigest()
    message = f"{vuln_id} ({severity}) in {package_ref}."
    if vuln.get("fixed_version"):
        message += f" Fix: upgrade to {vuln['fixed_version']}."
    return {
        "ruleId": vuln_id,
        "level": level,
        "kind": "fail",
        "message": {"text": message},
        "fingerprints": {"agent-bom/check/v1": fingerprint},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"pkg:{ecosystems[0] if ecosystems else 'generic'}/{package}@{version}"},
                    "region": {"startLine": 1, "startColumn": 1},
                }
            }
        ],
        "properties": properties,
    }


def _check_payload_to_sarif(payload: dict) -> dict:
    """Convert a package-check payload to SARIF 2.1.0."""
    package = payload.get("package") or "unknown"
    version = payload.get("version") or "unknown"
    ecosystems = payload.get("ecosystems") or []
    package_ref = f"{package}@{version}"
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    severity_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "none": "none",
        "unknown": "note",
    }

    for vuln in payload.get("vulnerabilities") or []:
        vuln_id = str(vuln.get("id") or "unknown")
        severity = str(vuln.get("severity") or "unknown").lower()
        level = severity_level.get(severity, "warning")
        properties = _check_sarif_properties(vuln, package, version, ecosystems, severity)

        rules.append(
            {
                "id": vuln_id,
                "shortDescription": {"text": f"{severity.upper()}: {vuln_id} in {package_ref}"},
                "fullDescription": {"text": str(vuln.get("summary") or f"Vulnerability {vuln_id}")},
                "helpUri": f"https://osv.dev/vulnerability/{vuln_id}",
                "defaultConfiguration": {"level": level},
                "properties": properties,
            }
        )
        results.append(_check_sarif_result(vuln, vuln_id, severity, level, package, version, ecosystems, properties))

    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agent-bom check",
                        "informationUri": "https://github.com/msaad00/agent-bom",
                        "semanticVersion": __version__,
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "schema_version": payload.get("schema_version"),
                    "document_type": payload.get("document_type"),
                    "verdict": payload.get("verdict"),
                    "exit_code": payload.get("exit_code"),
                    "package": package,
                    "version": version,
                    "ecosystems": ecosystems,
                    "vulnerability_count": payload.get("vulnerability_count"),
                },
            }
        ],
    }


def _write_check_output(
    payload: dict,
    output_path: str | None,
    *,
    agent_mode: bool,
    exit_code: int,
    output_format: str = "json",
) -> None:
    """Write package-check output in plain JSON or agent-mode envelope form."""
    if not agent_mode:
        if output_format == "sarif":
            _write_sarif_output(payload, output_path)
            return
        _write_json_output(payload, output_path)
        return

    from agent_bom.cli._agent_mode import command_success_envelope, dumps_envelope

    error_type = None
    if exit_code == 1:
        error_type = "unsafe_package"
    elif exit_code == 2:
        error_type = "incomplete_scan"
    envelope = command_success_envelope(
        command="check",
        data=payload,
        exit_code=exit_code,
        summary=_check_agent_summary(payload),
        confidence=_check_agent_confidence(payload),
        error_type=error_type,
    )
    text = dumps_envelope(envelope)
    if output_path and output_path != "-":
        Path(output_path).write_text(text, encoding="utf-8")
        return
    click.echo(text)


def _render_provenance_check(provenance: dict | None) -> dict[str, str]:
    """Normalize provenance verification into a stable CLI-facing status."""
    if provenance and provenance.get("has_provenance"):
        att_count = provenance.get("attestation_count", 0)
        files = provenance.get("files") or []
        if files:
            file_count = len(files) if isinstance(files, list) else 0
            detail = f"Release provenance present for all {file_count} file(s) ({att_count} attestation(s))"
        else:
            detail = f"Provenance attestation found ({att_count} attestation(s))"
        return {
            "status": "pass",
            "detail": detail,
        }

    status = str((provenance or {}).get("status") or "")
    if status == "not_published":
        return {
            "status": "missing",
            "detail": "No registry provenance attestation found for this release",
        }
    if status == "not_provenance":
        return {
            "status": "missing",
            "detail": "Attestations found, but none were SLSA/provenance attestations",
        }
    if status == "partial":
        att_count = (provenance or {}).get("attestation_count", 0)
        missing = (provenance or {}).get("missing_files") or []
        suffix = f"; missing: {', '.join(missing[:3])}" if missing else ""
        return {
            "status": "fail",
            "detail": f"Only partial release provenance found ({att_count} attestation(s)){suffix}",
        }
    if status == "unavailable":
        return {
            "status": "unavailable",
            "detail": "Provenance service unavailable",
        }
    return {
        "status": "unknown",
        "detail": "Could not determine provenance status",
    }


def _check_result_payload(
    *,
    name: str,
    version: str,
    ecosystems: list[str],
    verdict: str,
    message: str,
    exit_code: int,
    vulnerabilities: list | None = None,
    warnings: list[str] | None = None,
    exit_zero: bool = False,
    fail_on_severity: str | None = None,
    fail_on_severity_count: int | None = None,
    lookup_mode: str = "online",
    malicious_reason: str | None = None,
) -> dict:
    """Build machine-readable check output."""
    from agent_bom.scanners.package_check_result import PackageCheckResult, serialize_vulnerability

    result = PackageCheckResult(
        package=name,
        version=version,
        ecosystems=tuple(ecosystems),
        verdict=verdict,
        message=message,
        lookup_mode=lookup_mode,
        vulnerabilities=tuple(serialize_vulnerability(vuln) for vuln in vulnerabilities or []),
        warnings=tuple(warnings or []),
        is_malicious=verdict == "malicious",
        malicious_reason=malicious_reason,
        exit_code=exit_code,
    )
    return result.cli_payload(
        legacy_verdict=verdict,
        exit_zero=exit_zero,
        fail_on_severity=fail_on_severity,
        fail_on_severity_count=fail_on_severity_count,
    )


def _format_vulnerability_count(count: int) -> str:
    return f"{count} vulnerability found" if count == 1 else f"{count} vulnerabilities found"


def _vulns_at_or_above(vulnerabilities: list, threshold: str | None) -> list:
    if not threshold:
        return list(vulnerabilities)
    return [vuln for vuln in vulnerabilities if severity_at_or_above(str(vuln.severity.value), threshold)]


def _resolve_check_ecosystems(name: str, version: str, ecosystem: Optional[str], detected_eco: str) -> list[str]:
    """Return the ecosystems that `check` should scan."""
    if ecosystem:
        return [detected_eco]
    if name.startswith("@") or "." in name or "_" in name:
        return [detected_eco]

    resolved = _detect_ecosystem(name, version)
    if resolved:
        return [resolved]

    raise click.UsageError(f"Ambiguous package name '{name}'. Specify --ecosystem pypi or --ecosystem npm for a trustworthy verdict.")


def _maven_coordinate_error(name: str, ecosystem: str) -> str | None:
    """Return a fail-closed message when a Maven package lacks its namespace.

    OSV identifies Maven artifacts by ``group:artifact``. Querying a bare
    artifact name can return no rows and must never be presented as a clean
    result, because another group may own the vulnerable artifact.
    """
    if ecosystem.lower() != "maven":
        return None
    parts = name.split(":")
    if len(parts) == 2 and all(part.strip() for part in parts):
        return None
    return (
        f"Maven package '{name}' is missing its group:artifact coordinate. "
        "Use --ecosystem maven with a fully qualified coordinate, for example "
        "org.apache.logging.log4j:log4j-core@2.14.1; a bare artifact name "
        "cannot produce a trustworthy clean verdict."
    )


def _package_spec_error(name: str, ecosystem: str) -> str | None:
    """Return a fail-closed message for syntactically invalid package names."""
    maven_error = _maven_coordinate_error(name, ecosystem)
    if maven_error:
        return maven_error

    try:
        from agent_bom.security import SecurityError, validate_package_name

        if ecosystem.lower() in {"npm", "pypi", "go", "cargo"}:
            validate_package_name(name, ecosystem.lower())
            return None
    except SecurityError:
        pass

    # Other ecosystems do not share one package-name grammar, but shell and
    # requirement operators are never part of a package name after parsing.
    if not name.strip() or any(char in name for char in "\r\n=<>!"):
        return f"Invalid {ecosystem} package name '{name}'. Provide a package name followed by an explicit version."
    return None
