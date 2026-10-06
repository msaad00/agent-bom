"""Inventory and timestamps for the retained finding snapshot scope."""

from typing import Any

from agent_bom.api.findings_current import _ScanJobLike


def snapshot_metadata(jobs: list[_ScanJobLike], rows: list[dict[str, Any]]) -> dict[str, Any]:
    agent_names: set[str] = set()
    package_keys: set[tuple[str, str, str]] = set()
    summary_agent_counts: list[int] = []
    summary_package_counts: list[int] = []
    generated_values: list[str] = []
    completed_scan_ids: set[str] = set()
    for job in jobs:
        result = job.result if isinstance(job.result, dict) else {}
        completed_scan_ids.add(str(result.get("scan_id") or job.job_id))
        for agent in result.get("agents", []) if isinstance(result.get("agents"), list) else []:
            if isinstance(agent, dict) and str(agent.get("name") or "").strip():
                agent_names.add(str(agent["name"]).strip())
        for package in result.get("packages", []) if isinstance(result.get("packages"), list) else []:
            if isinstance(package, dict):
                package_keys.add(
                    (
                        str(package.get("name") or ""),
                        str(package.get("version") or ""),
                        str(package.get("ecosystem") or ""),
                    )
                )
        raw_summary = result.get("summary")
        summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
        if isinstance(summary.get("total_agents"), int):
            summary_agent_counts.append(summary["total_agents"])
        if isinstance(summary.get("total_packages"), int):
            summary_package_counts.append(summary["total_packages"])
        generated = result.get("generated_at") or job.completed_at
        if isinstance(generated, str) and generated:
            generated_values.append(generated)

    # Bulk-ingested/current findings can carry useful inventory identity even
    # when no full report envelope exists. Count the observed identities; never
    # manufacture placeholder agents or packages to match a summary scalar.
    for row in rows:
        raw_agents = row.get("affected_agents")
        if isinstance(raw_agents, list):
            agent_names.update(str(name).strip() for name in raw_agents if str(name).strip())
        raw_asset = row.get("asset")
        asset = raw_asset if isinstance(raw_asset, dict) else {}
        package_value = str(row.get("package") or row.get("package_name") or "").strip()
        if package_value:
            package_keys.add((package_value, str(row.get("package_version") or ""), str(row.get("ecosystem") or "")))
        elif str(asset.get("asset_type") or "").lower() == "package" and str(asset.get("name") or "").strip():
            package_keys.add((str(asset["name"]).strip(), "", ""))

    return {
        "total_agents": len(agent_names) if agent_names else max(summary_agent_counts, default=0),
        "total_packages": len(package_keys) if package_keys else max(summary_package_counts, default=0),
        "generated_at": max(generated_values, default=""),
        "scan_ids": sorted(completed_scan_ids | {str(row.get("scan_id")) for row in rows if row.get("scan_id")}),
        "completed_scan_count": len(jobs),
    }
