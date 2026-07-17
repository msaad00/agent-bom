"""Vector-database evidence integrity across CLI context and JSON output."""

from __future__ import annotations

import json
from io import StringIO

from rich.console import Console

from agent_bom.cli.agents._cloud import run_benchmarks
from agent_bom.cli.agents._context import ScanContext
from agent_bom.cloud.vector_db import VectorDBResult
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import export_json


def test_vector_scan_retains_pinecone_in_report_without_api_key(monkeypatch, tmp_path) -> None:
    api_key = "pcsk-test-secret-must-not-leak"
    monkeypatch.setenv("PINECONE_API_KEY", api_key)
    self_hosted = VectorDBResult(
        db_type="qdrant",
        host="127.0.0.1",
        port=6333,
        is_reachable=True,
        requires_auth=True,
        version="1.9.0",
        collection_count=2,
        is_loopback=True,
    )
    monkeypatch.setattr("agent_bom.cloud.vector_db.discover_vector_dbs", lambda: [self_hosted])

    def _pinecone_get(path: str, supplied_key: str, timeout: int = 3) -> tuple[int, dict]:
        assert path == "/indexes"
        assert supplied_key == api_key
        assert timeout == 3
        return (
            200,
            {
                "indexes": [
                    {
                        "name": "prod-vectors",
                        "dimension": 1536,
                        "metric": "cosine",
                        "spec": {"serverless": {"region": "us-east-1"}},
                        "status": {"state": "ready", "ready": True},
                    }
                ]
            },
        )

    monkeypatch.setattr("agent_bom.cloud.vector_db._pinecone_get", _pinecone_get)

    output = StringIO()
    ctx = ScanContext(con=Console(file=output, force_terminal=False, width=120))
    run_benchmarks(
        ctx,
        skill_only=False,
        verify_model_hashes=False,
        project=None,
        hf_token=None,
        aws_cis_benchmark=False,
        aws_region=None,
        aws_profile=None,
        snowflake_cis_benchmark=False,
        snowflake_authenticator=None,
        azure_cis_benchmark=False,
        azure_subscription=None,
        gcp_cis_benchmark=False,
        gcp_project=None,
        databricks_security=False,
        aisvs_flag=False,
        vector_db_scan=True,
        gpu_scan_flag=False,
        gpu_k8s_context=None,
        no_dcgm_probe=False,
        smithery_flag=False,
        smithery_token=None,
        mcp_registry_flag=False,
        snyk_flag=False,
        snyk_token=None,
        snyk_org=None,
        cortex_observability=False,
    )

    report = AIBOMReport(vector_db_scan_data=[result.to_dict() for result in ctx.vector_db_results])
    report_path = tmp_path / "vector-evidence.json"
    export_json(report, str(report_path))
    round_tripped = json.loads(report_path.read_text(encoding="utf-8"))

    assert [item["db_type"] for item in round_tripped["vector_db_scan"]] == ["qdrant", "pinecone"]
    assert round_tripped["vector_db_scan"][1]["index_name"] == "prod-vectors"
    assert api_key not in json.dumps(round_tripped)
    assert api_key not in output.getvalue()
