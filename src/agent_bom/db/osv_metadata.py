"""OSV advisory relationships for local database ingestion."""

from __future__ import annotations

from agent_bom.advisory_ids import upstream_advisory_ids


def osv_relationship_metadata(data: dict, db_specific: object) -> dict[str, str]:
    cwes = db_specific.get("cwe_ids", []) if isinstance(db_specific, dict) else []
    aliases = data.get("aliases", [])
    return {
        "cwe_ids": ",".join(c for c in cwes if isinstance(c, str) and c.startswith("CWE-")) if isinstance(cwes, list) else "",
        "aliases": ",".join(a for a in aliases if isinstance(a, str)) if isinstance(aliases, list) else "",
        "upstream_ids": ",".join(upstream_advisory_ids(data.get("upstream"))),
    }
