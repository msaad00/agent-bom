"""Optional real-image startup contract for the standalone Snowpark API."""

import os
import secrets
import subprocess
import time

import pytest


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_TEST_SNOWPARK_IMAGE"), reason="requires explicitly built Snowpark image")
def test_snowpark_image_has_writable_state_and_starts_without_root():
    env = dict(os.environ, AGENT_BOM_API_KEY=secrets.token_hex(32))
    image = os.environ["AGENT_BOM_TEST_SNOWPARK_IMAGE"]
    container = subprocess.check_output(["docker", "run", "-d", "-e", "AGENT_BOM_API_KEY", image], env=env, text=True).strip()
    try:
        for _ in range(40):
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    container,
                    "python",
                    "-c",
                    "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8422/health')",
                ],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                break
            time.sleep(0.25)
        else:
            pytest.fail("Snowpark API did not become healthy with its default non-root state directory")
        subprocess.run(
            [
                "docker",
                "exec",
                container,
                "python",
                "-c",
                "import os; assert os.getuid() != 0; assert os.access(os.environ['AGENT_BOM_STATE_DIR'], os.W_OK)",
            ],
            check=True,
            capture_output=True,
            timeout=10,
        )
    finally:
        subprocess.run(["docker", "rm", "-f", container], capture_output=True, check=True, timeout=20)
