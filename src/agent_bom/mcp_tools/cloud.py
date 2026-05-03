"""Cloud tools — vector_db_scan, gpu_infra_scan implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def vector_db_scan_impl(
    *,
    hosts: str | None = None,
    _truncate_response,
) -> str:
    """Implementation of the vector_db_scan tool."""
    try:
        from agent_bom.cloud.vector_db import discover_pinecone, discover_vector_dbs

        host_list = [h.strip() for h in hosts.split(",")] if hosts else None
        self_hosted = discover_vector_dbs(hosts=host_list)
        pinecone_results = discover_pinecone()
        all_results = [r.to_dict() for r in self_hosted] + [r.to_dict() for r in pinecone_results]
        return _truncate_response(
            json.dumps(
                {
                    "databases_found": len(all_results),
                    "self_hosted_count": len(self_hosted),
                    "cloud_count": len(pinecone_results),
                    "results": all_results,
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def gpu_infra_scan_impl(
    *,
    k8s_context: str | None = None,
    probe_dcgm: bool = True,
    _truncate_response,
) -> str:
    """Implementation of the gpu_infra_scan tool."""
    try:
        from agent_bom.cloud.gpu_infra import scan_gpu_infra

        report = await scan_gpu_infra(k8s_context=k8s_context, probe_dcgm=probe_dcgm)
        result = {
            "risk_summary": report.risk_summary,
            "gpu_containers": [
                {
                    "container_id": c.container_id,
                    "name": c.name,
                    "image": c.image,
                    "status": c.status,
                    "is_nvidia_base": c.is_nvidia_base,
                    "cuda_version": c.cuda_version,
                    "cudnn_version": c.cudnn_version,
                    "gpu_requested": c.gpu_requested,
                }
                for c in report.gpu_containers
            ],
            "k8s_gpu_nodes": [
                {
                    "name": n.name,
                    "gpu_vendor": n.gpu_vendor,
                    "gpu_capacity": n.gpu_capacity,
                    "gpu_allocatable": n.gpu_allocatable,
                    "gpu_allocated": n.gpu_allocated,
                    "cuda_driver_version": n.cuda_driver_version,
                }
                for n in report.gpu_nodes
            ],
            "dcgm_endpoints": [
                {
                    "host": ep.host,
                    "port": ep.port,
                    "url": ep.url,
                    "authenticated": ep.authenticated,
                    "gpu_count": ep.gpu_count,
                    "risk": "unauthenticated GPU metrics exposure" if not ep.authenticated else "ok",
                }
                for ep in report.dcgm_endpoints
            ],
            "driver_findings": report.driver_findings,
            "firmware_findings": report.firmware_findings,
            "warnings": report.warnings,
        }
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
