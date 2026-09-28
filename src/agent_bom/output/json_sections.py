"""Per-entity JSON rows for the ``agents`` section of the scan report.

Shared by the full report (:func:`agent_bom.output.json_fmt.to_json`) and the
graph evidence projection, so both serialize the inventory identically.
"""

from __future__ import annotations

from typing import Any

from agent_bom.asset_provenance import (
    agent_discovery_provenance,
    package_discovery_provenance,
    package_version_provenance,
    sanitize_discovery_provenance,
)
from agent_bom.mcp_blocklist import sanitize_security_intelligence_entry
from agent_bom.models import AIBOMReport, Severity
from agent_bom.security import (
    sanitize_command_args,
    sanitize_path_label,
    sanitize_security_warnings,
    sanitize_url,
)


def _severity_state(severity: Severity) -> str:
    """Stable severity-state label for structured consumers."""
    return "pending" if severity == Severity.UNKNOWN else "scored"


def _severity_label(severity: Severity) -> str:
    """Human-friendly label that distinguishes advisory-only findings."""
    return "advisory" if severity == Severity.UNKNOWN else severity.value


def _package_occurrence_to_dict(occurrence) -> dict[str, object]:
    """Serialize package provenance observations without importing parser internals."""
    if hasattr(occurrence, "to_dict"):
        return occurrence.to_dict()
    return {
        "layer_index": getattr(occurrence, "layer_index", None),
        "layer_id": getattr(occurrence, "layer_id", None),
        "layer_path": getattr(occurrence, "layer_path", None),
        "package_path": getattr(occurrence, "package_path", None),
        "created_by": getattr(occurrence, "created_by", None),
        "dockerfile_instruction": getattr(occurrence, "dockerfile_instruction", None),
    }


def _vulnerability_json(v: Any) -> dict[str, Any]:
    return {
        "id": v.id,
        "summary": v.summary,
        "severity": v.severity.value,
        "severity_label": _severity_label(v.severity),
        "severity_state": _severity_state(v.severity),
        "severity_source": v.severity_source,
        "advisory_sources": v.all_advisory_sources,
        "primary_advisory_source": v.all_advisory_sources[0] if v.all_advisory_sources else None,
        "advisory_coverage_state": v.advisory_coverage_state,
        "match_confidence_tier": v.match_confidence_tier,
        "confidence": v.confidence,
        "cvss_score": v.cvss_score,
        "epss_score": v.epss_score,
        "epss_percentile": v.epss_percentile,
        "is_kev": v.is_kev,
        "kev_date_added": v.kev_date_added,
        "kev_due_date": v.kev_due_date,
        "exploit_likelihood": v.exploit_likelihood,
        "published_at": v.published_at,
        "modified_at": v.modified_at,
        "aliases": v.aliases,
        "exploitability": v.exploitability,
        "cwe_ids": v.cwe_ids,
        "fixed_version": v.fixed_version,
        "references": v.references,
        "nvd_published": v.nvd_published,
        "nvd_modified": v.nvd_modified,
        "nvd_status": v.nvd_status,
        "vex_status": v.vex_status,
        "vex_justification": v.vex_justification,
        "compliance_tags": v.compliance_tags,
    }


def _package_json(pkg: Any, agent: Any) -> dict[str, Any]:
    return {
        "name": pkg.name,
        "stable_id": pkg.stable_id,
        "canonical_id": pkg.canonical_id,
        "version": pkg.version,
        "ecosystem": pkg.ecosystem,
        "purl": pkg.purl,
        "source_package": pkg.source_package,
        "distro_name": pkg.distro_name,
        "distro_version": pkg.distro_version,
        "occurrence_count": len(pkg.occurrences),
        "occurrences": [_package_occurrence_to_dict(occ) for occ in pkg.occurrences],
        "introduced_in_layer": (_package_occurrence_to_dict(pkg.primary_occurrence) if pkg.primary_occurrence else None),
        "is_direct": pkg.is_direct,
        "parent_package": pkg.parent_package,
        "dependency_depth": pkg.dependency_depth,
        "dependency_scope": pkg.dependency_scope,
        "reachability_evidence": pkg.reachability_evidence,
        "resolved_from_registry": pkg.resolved_from_registry,
        "version_source": pkg.version_source,
        "declared_version": pkg.declared_version,
        "resolved_version": pkg.resolved_version,
        "version_confidence": pkg.version_confidence,
        "version_resolved_at": pkg.version_resolved_at,
        "version_evidence": pkg.version_evidence or None,
        "version_conflicts": pkg.version_conflicts or None,
        "version_provenance": package_version_provenance(
            pkg,
            inherited=agent_discovery_provenance(agent),
        ),
        "discovery_provenance": package_discovery_provenance(
            pkg,
            inherited=agent_discovery_provenance(agent),
        ),
        "floating_reference": pkg.floating_reference,
        "floating_reference_reason": pkg.floating_reference_reason,
        "is_malicious": pkg.is_malicious,
        "malicious_reason": pkg.malicious_reason,
        "registry_version": pkg.registry_version,
        "license": pkg.license,
        "license_expression": pkg.license_expression,
        "supplier": pkg.supplier,
        "author": pkg.author,
        "description": pkg.description,
        "homepage": pkg.homepage,
        "repository_url": pkg.repository_url,
        "download_url": pkg.download_url,
        "copyright_text": pkg.copyright_text,
        "deps_dev_resolved": pkg.deps_dev_resolved,
        # --verify-integrity verdict; null means the
        # check never ran (not "ran and failed").
        "integrity_verified": pkg.integrity_verified,
        "provenance_attested": pkg.provenance_attested,
        "provenance_source": pkg.provenance_source,
        # Why the verdict is what it is. "unavailable"
        # means the registry never answered — not that
        # the attestation is missing.
        "provenance_status": pkg.provenance_status,
        "scorecard_score": pkg.scorecard_score,
        "scorecard_checks": pkg.scorecard_checks or None,
        "scorecard_repo": pkg.scorecard_repo,
        "scorecard_lookup_state": pkg.scorecard_lookup_state,
        "scorecard_lookup_reason": pkg.scorecard_lookup_reason,
        "vulnerability_count": len(pkg.vulnerabilities),
        "vulnerabilities": [_vulnerability_json(v) for v in pkg.vulnerabilities],
    }


def _tool_json(t: Any) -> dict[str, Any]:
    return {
        "name": t.name,
        "stable_id": t.stable_id,
        "canonical_id": t.canonical_id,
        "fingerprint": t.fingerprint,
        "description": t.description,
        "discovery_source": t.discovery_source,
        "discovery_confidence": t.discovery_confidence,
        "schema_findings": t.schema_findings,
        "schema_rule_findings": t.schema_rule_findings,
        "risk_score": t.risk_score,
    }


def _resource_json(r: Any) -> dict[str, Any]:
    return {
        "uri": r.uri,
        "stable_id": r.stable_id,
        "canonical_id": r.canonical_id,
        "fingerprint": r.fingerprint,
        "name": r.name,
        "description": r.description,
        "mime_type": r.mime_type,
        "content_findings": r.content_findings,
        "risk_score": r.risk_score,
    }


def _prompt_json(p: Any) -> dict[str, Any]:
    return {
        "name": p.name,
        "stable_id": p.stable_id,
        "canonical_id": p.canonical_id,
        "fingerprint": p.fingerprint,
        "description": p.description,
        "arguments": p.arguments,
        "content_findings": p.content_findings,
        "risk_score": p.risk_score,
    }


def _server_json(server: Any, agent: Any) -> dict[str, Any]:
    return {
        "name": server.name,
        "stable_id": server.stable_id,
        "canonical_id": server.canonical_id,
        "surface": server.surface.value,
        "fingerprint": server.fingerprint,
        "command": server.command,
        "args": sanitize_command_args(server.args),
        "transport": server.transport.value,
        "url": sanitize_url(server.url),
        "auth_mode": server.auth_mode,
        "mcp_version": server.mcp_version,
        "has_credentials": server.has_credentials,
        "credential_env_vars": server.credential_names,
        "identity_bindings": [binding.to_dict() for binding in server.identity_bindings],
        "registry_verified": server.registry_verified,
        "registry_badge": "verified" if server.registry_verified else "unknown",
        "security_blocked": server.security_blocked,
        "security_warnings": sanitize_security_warnings(server.security_warnings),
        "security_intelligence": [
            sanitize_security_intelligence_entry(item) for item in (server.security_intelligence or []) if isinstance(item, dict)
        ],
        "discovery_sources": server.discovery_sources,
        "discovery_provenance": sanitize_discovery_provenance(
            server.discovery_provenance,
            defaults=agent_discovery_provenance(agent),
        ),
        "tools": [_tool_json(t) for t in server.tools],
        "resources": [_resource_json(r) for r in server.resources],
        "prompts": [_prompt_json(p) for p in server.prompts],
        "packages": [_package_json(pkg, agent) for pkg in server.packages],
        "permission_profile": (
            {
                "runs_as_root": server.permission_profile.runs_as_root,
                "container_privileged": server.permission_profile.container_privileged,
                "privilege_level": server.permission_profile.privilege_level,
                "tool_permissions": server.permission_profile.tool_permissions,
                "capabilities": server.permission_profile.capabilities,
                "network_access": server.permission_profile.network_access,
                "filesystem_write": server.permission_profile.filesystem_write,
                "shell_access": server.permission_profile.shell_access,
            }
            if server.permission_profile
            else None
        ),
    }


def _agent_json(agent: Any) -> dict[str, Any]:
    return {
        "name": agent.name,
        "stable_id": agent.stable_id,
        "canonical_id": agent.canonical_id,
        "previous_canonical_ids": agent.previous_canonical_ids,
        "agent_type": agent.agent_type.value,
        "type": agent.agent_type.value,
        "config_path": sanitize_path_label(agent.config_path) if agent.config_path else "",
        "source": agent.source,
        "status": agent.status.value,
        "discovered_at": agent.discovered_at,
        "last_seen": agent.last_seen,
        "discovery_provenance": agent_discovery_provenance(agent),
        "metadata": agent.metadata,
        "automation_settings": agent.automation_settings,
        "mcp_servers": [_server_json(server, agent) for server in agent.mcp_servers],
    }


def agents_json(report: AIBOMReport) -> list[dict[str, Any]]:
    """Serialize every agent with its servers, tools, packages and vulnerabilities."""
    return [_agent_json(agent) for agent in report.agents]
