"""Smoke test a running agent-bom control plane with the Python client.

Environment:
    AGENT_BOM_BASE_URL   API base URL, for example http://127.0.0.1:8422
    AGENT_BOM_API_KEY    Optional x-api-key value
    AGENT_BOM_BEARER_TOKEN Optional bearer token; mutually exclusive with API key
    AGENT_BOM_TENANT_ID  Optional tenant scope
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Sequence

from agent_bom import AgentBomApiError, AgentBomClient


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Smoke test an agent-bom API with the Python client.")
    parser.add_argument("--base-url", default=os.environ.get("AGENT_BOM_BASE_URL", "http://127.0.0.1:8422"))
    parser.add_argument("--api-key", default=os.environ.get("AGENT_BOM_API_KEY"))
    parser.add_argument("--bearer-token", default=os.environ.get("AGENT_BOM_BEARER_TOKEN"))
    parser.add_argument("--tenant-id", default=os.environ.get("AGENT_BOM_TENANT_ID"))
    return parser


def run_smoke(*, base_url: str, api_key: str | None, bearer_token: str | None, tenant_id: str | None) -> dict[str, object]:
    """Call stable read endpoints and return a compact adoption-smoke envelope."""

    with AgentBomClient(base_url=base_url, api_key=api_key, bearer_token=bearer_token, tenant_id=tenant_id) as client:
        health = client.health()
        manifest = client.agent_manifest()
        runtime = client.runtime_production_index()
        intel_sources = client.intel_sources()
        deploy_decision = client.should_i_deploy("flask@2.0.0", block_risk=80)

    sources = intel_sources.get("sources", [])
    return {
        "status": "ok",
        "health_status": health.get("status"),
        "manifest_schema": manifest.get("schema_version"),
        "runtime_schema": runtime.get("schema_version"),
        "intel_sources": len(sources) if isinstance(sources, list) else 0,
        "deploy_decision": deploy_decision.get("decision"),
    }


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = run_smoke(
            base_url=args.base_url,
            api_key=args.api_key,
            bearer_token=args.bearer_token,
            tenant_id=args.tenant_id,
        )
    except AgentBomApiError as exc:
        sys.stdout.write(json.dumps({"status": "error", "status_code": exc.status_code, "body": exc.body}, sort_keys=True) + "\n")
        return 1
    sys.stdout.write(json.dumps(result, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
