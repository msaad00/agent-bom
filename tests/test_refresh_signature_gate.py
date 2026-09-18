"""Floating-image signatures must tolerate propagation delays and fail closed."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("job", ["refresh-latest", "refresh-ui-latest", "refresh-collector-latest"])
@pytest.mark.parametrize("succeeds_on", [2, 99])
def test_refresh_signature_verification_is_bounded_and_preserves_identity(tmp_path: Path, job: str, succeeds_on: int) -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/refresh-latest-container.yml").read_text())
    step = next(step for step in workflow["jobs"][job]["steps"] if step.get("name", "").startswith("Verify refreshed"))
    body = step["run"].replace("${{ github.repository }}", "owner/repository").replace("${{ github.ref }}", "refs/heads/main")
    body = re.sub(r"\$\{\{ steps\.[^}]+\.outputs.digest \}\}", "sha256:" + "a" * 64, body)
    mock = tmp_path / "cosign"
    mock.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$CALL_LOG"\nattempt=$(wc -l < "$CALL_LOG")\n[ "$attempt" -ge "$SUCCEEDS_ON" ]\n')
    mock.chmod(0o755)
    sleep = tmp_path / "sleep"
    sleep.write_text("#!/bin/sh\nexit 0\n")
    sleep.chmod(0o755)
    calls = tmp_path / "calls"
    env = {**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}", "CALL_LOG": str(calls), "SUCCEEDS_ON": str(succeeds_on)}
    result = subprocess.run(["bash", "-e", "-o", "pipefail", "-c", body], env=env, capture_output=True, text=True, timeout=5)
    attempts = calls.read_text().splitlines()
    assert (result.returncode == 0) == (succeeds_on == 2)
    assert len(attempts) == (2 if succeeds_on == 2 else 3)
    for attempt in attempts:
        assert attempt.startswith("verify ")
        assert (
            "--certificate-identity https://github.com/owner/repository/.github/workflows/refresh-latest-container.yml@refs/heads/main"
            in attempt
        )
        assert "--certificate-oidc-issuer https://token.actions.githubusercontent.com" in attempt
        assert "@sha256:" + "a" * 64 in attempt
        assert "--insecure" not in attempt
