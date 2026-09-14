"""Capture Overview API fixtures from a fresh, offline synthetic demo estate.

Run from the repository root with ``uv run python ui/scripts/generate-overview-proof.py``.
The temporary application never binds a network port or uses operator state.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import secrets
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))


def main() -> None:
    logging.disable(logging.CRITICAL)
    with tempfile.TemporaryDirectory(prefix="agent-bom-overview-proof-") as directory:
        # Imports below construct process-global stores. Start from isolated
        # configuration before importing the app; never inherit cloud secrets.
        os.environ.clear()
        key = secrets.token_hex(32)
        os.environ.update(
            {
                "HOME": directory,
                "PATH": os.defpath,
                "AGENT_BOM_STATE_DIR": directory,
                "AGENT_BOM_DB": str(Path(directory) / "demo.db"),
                "AGENT_BOM_DEMO_ESTATE": "1",
                "AGENT_BOM_API_KEY": key,
                "AGENT_BOM_AUDIT_HMAC_KEY": secrets.token_hex(32),
                "AGENT_BOM_NO_AUTO_CONNECTIONS_KEY": "1",
            }
        )
        from starlette.testclient import TestClient

        from agent_bom.api.server import app

        responses = {}
        with TestClient(app, headers={"X-API-Key": key}) as client:
            for endpoint in ["/v1/overview", "/v1/posture", "/v1/posture/counts", "/v1/compliance", "/v1/jobs", "/v1/agents"]:
                response = client.get(endpoint)
                response.raise_for_status()
                responses[endpoint] = response.json()
            for job in responses["/v1/jobs"]["jobs"]:
                endpoint = f"/v1/scan/{job['job_id']}"
                response = client.get(endpoint)
                response.raise_for_status()
                responses[endpoint] = response.json()

        payload = {
            "evidence": "Synthetic enterprise demo; generated offline through the application API. No live cloud collection.",
            "generator": "uv run python ui/scripts/generate-overview-proof.py",
            "captured_at": responses["/v1/overview"]["headline"]["latest_scan_at"],
            "responses": responses,
        }
        serialized = json.dumps(payload, indent=2) + "\n"
        if key in serialized:
            raise RuntimeError("Authentication material must not enter the fixture")
        destination = ROOT / "ui/fixtures/overview-proof.json.gz"
        destination.parent.mkdir(exist_ok=True)
        destination.write_bytes(gzip.compress(serialized.encode(), mtime=0))
        sys.stdout.write(f"Generated {destination.relative_to(ROOT)} from an isolated synthetic estate\n")


if __name__ == "__main__":
    main()
