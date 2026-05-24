"""Live smoke coverage for the documented Python control-plane example."""

from __future__ import annotations

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "python_sdk" / "control_plane_smoke.py"


def _load_example() -> ModuleType:
    spec = importlib.util.spec_from_file_location("control_plane_smoke", EXAMPLE)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _Handler(BaseHTTPRequestHandler):
    seen_headers: list[dict[str, str]] = []

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        _Handler.seen_headers.append(dict(self.headers))
        path = urlparse(self.path).path
        payloads = {
            "/health": {"status": "ok"},
            "/v1/agent-bom/manifest": {"schema_version": "agent-bom.manifest/v1", "agents": []},
            "/v1/runtime/production-index": {"schema_version": "runtime.production_index.v1", "status": "ok"},
            "/v1/intel/sources": {"schema_version": "intel.sources.v1", "sources": [{"name": "osv"}]},
        }
        payload = payloads.get(path)
        if payload is None:
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        _Handler.seen_headers.append(dict(self.headers))
        path = urlparse(self.path).path
        if path != "/v1/graph/should-i-deploy":
            self.send_response(404)
            self.end_headers()
            return
        body = json.dumps({"decision": "allow"}).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_python_sdk_control_plane_smoke_example_runs_against_local_http_server() -> None:
    _Handler.seen_headers = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        module = _load_example()
        result = module.run_smoke(
            base_url=f"http://127.0.0.1:{server.server_port}",
            api_key="dev-key",
            bearer_token=None,
            tenant_id="tenant-a",
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    assert result == {
        "health_status": "ok",
        "intel_sources": 1,
        "deploy_decision": "allow",
        "manifest_schema": "agent-bom.manifest/v1",
        "runtime_schema": "runtime.production_index.v1",
        "status": "ok",
    }
    assert _Handler.seen_headers
    for headers in _Handler.seen_headers:
        normalized = {key.lower(): value for key, value in headers.items()}
        assert normalized["x-api-key"] == "dev-key"
        assert normalized["x-agent-bom-tenant-id"] == "tenant-a"
