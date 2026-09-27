"""Deterministic reconciliation of advisory aliases across scanner sources."""

from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import asdict

from agent_bom.advisory_ids import derive_cve_from_advisory_id
from agent_bom.core.severity import severity_rank
from agent_bom.models import Vulnerability


def advisory_keys(vuln: Vulnerability) -> set[str]:
    keys = {value.strip() for value in [vuln.id, *vuln.aliases] if value.strip()}
    return keys | {cve for key in keys if (cve := derive_cve_from_advisory_id(key))}


def _external_only(vuln: Vulnerability) -> bool:
    return bool(vuln.advisory_sources) and all(source.startswith("external") for source in vuln.advisory_sources)


def _advisory_origin(vuln: Vulnerability) -> str:
    # Merged aliases are sorted, so they cannot identify the winning source.
    if vuln.severity_source and vuln.severity_source.startswith("advisory:"):
        return vuln.severity_source.removeprefix("advisory:")
    if not vuln.id.upper().startswith("CVE-"):
        return vuln.id
    # The input canonicalizer retains the original advisory as the first alias.
    return next((alias for alias in vuln.aliases if not alias.upper().startswith("CVE-")), vuln.id)


def merge_advisory_clusters(records: list[Vulnerability]) -> list[Vulnerability]:
    """Collapse transitive aliases; retain the highest authoritative severity.

    Advisory DB evidence supersedes an external-only report. Within that tier,
    severity, score, original advisory ID and serialized content break ties in
    that order. Score, vector and fix always come from the same representative;
    provenance, references and affected symbols retain the whole cluster.
    """
    parents = list(range(len(records)))

    def root(index: int) -> int:
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    owners: dict[str, int] = {}
    for index, record in enumerate(records):
        for key in advisory_keys(record):
            if key in owners:
                parents[root(index)] = root(owners[key])
            else:
                owners[key] = index
    groups: dict[int, list[Vulnerability]] = {}
    for index, record in enumerate(records):
        groups.setdefault(root(index), []).append(record)

    merged: list[Vulnerability] = []
    for cluster in groups.values():
        authoritative = [record for record in cluster if not _external_only(record)] or cluster
        representative = min(
            authoritative,
            key=lambda record: (
                -severity_rank(record.severity),
                -(record.cvss_score if record.cvss_score is not None else -1),
                _advisory_origin(record),
                json.dumps(asdict(record), sort_keys=True, default=str),
            ),
        )
        result = deepcopy(representative)
        keys = set().union(*(advisory_keys(record) for record in cluster))
        cves = sorted(key for key in keys if key.upper().startswith("CVE-"))
        result.id = cves[0] if cves else min(keys)
        result.aliases = sorted(keys - {result.id})
        if len(cluster) > 1 or result.id != representative.id:
            result.severity_source = f"advisory:{_advisory_origin(representative)}"
        for field in ("advisory_sources", "references", "cwe_ids", "affected_symbols"):
            setattr(result, field, sorted({value for record in cluster for value in getattr(record, field)}))
        paths = {path for record in cluster for path in record.affected_symbols_by_path}
        result.affected_symbols_by_path = {
            path: sorted({symbol for record in cluster for symbol in record.affected_symbols_by_path.get(path, [])})
            for path in sorted(paths)
        }
        result.is_kev = any(record.is_kev for record in cluster)
        for field in ("kev_date_added", "kev_due_date"):
            values = [getattr(record, field) for record in cluster if record.is_kev and getattr(record, field)]
            if values:
                setattr(result, field, min(values))
        merged.append(result)
    return sorted(merged, key=lambda record: record.id)
