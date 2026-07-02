from __future__ import annotations

import os
import subprocess
from pathlib import Path

SCRIPT = Path("scripts/deploy/hosted_poc_smoke.sh")


def test_hosted_poc_smoke_requires_url_and_key() -> None:
    env = os.environ.copy()
    for name in ("AGENT_BOM_SMOKE_URL", "NEXT_PUBLIC_API_URL", "AGENT_BOM_SMOKE_API_KEY", "AGENT_BOM_API_KEY"):
        env.pop(name, None)

    result = subprocess.run(["bash", str(SCRIPT)], check=False, capture_output=True, text=True, env=env)

    assert result.returncode == 1
    assert "AGENT_BOM_SMOKE_URL" in result.stderr


def test_hosted_poc_smoke_hits_core_customer_zero_surfaces(tmp_path: Path) -> None:
    calls = tmp_path / "curl-calls.txt"
    fake_curl = tmp_path / "curl"
    fake_curl.write_text(
        '#!/usr/bin/env bash\nprintf \'%s\\n\' "$*" >> "$CURL_CALLS"\nexit 0\n',
        encoding="utf-8",
    )
    fake_curl.chmod(0o755)
    env = os.environ.copy()
    env.update(
        {
            "PATH": f"{tmp_path}:{env['PATH']}",
            "CURL_CALLS": str(calls),
            "AGENT_BOM_SMOKE_URL": "https://demo.agent-bom.com",
            "AGENT_BOM_SMOKE_API_KEY": "abom_test",
            "AGENT_BOM_SMOKE_CONNECTION_ID": "conn-123",
            "AGENT_BOM_SMOKE_RUN_CONNECTION_SCAN": "1",
        }
    )

    result = subprocess.run(["bash", str(SCRIPT)], check=False, capture_output=True, text=True, env=env)

    assert result.returncode == 0
    output = calls.read_text(encoding="utf-8")
    for path in (
        "/health",
        "/v1/auth/me",
        "/v1/overview",
        "/v1/jobs",
        "/v1/graph/snapshots",
        "/v1/compliance",
        "/v1/audit/integrity",
        "/v1/cloud/connections/conn-123/test",
        "/v1/cloud/connections/conn-123/scan",
    ):
        assert path in output
