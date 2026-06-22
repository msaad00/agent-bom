"""Regression guard for the xdist auth-state leak.

A test that sets an auth-influencing env var (via tests/auth_helpers or a raw
os.environ assignment) and then errors before its own cleanup must NOT leak that
var into the next test on the same worker — otherwise the next test's open
endpoint returns 401 instead of 200 (the intermittent ``assert 401 == 200``
flake). The autouse fixture in conftest snapshots and restores the auth env
around every test; these two tests prove a leak in the first does not reach the
second.
"""

import os

from tests.auth_helpers import enable_trusted_proxy_env


def test_auth_env_leak_setup():
    # Deliberately enable auth and do NOT disable it (simulates a test that
    # errors before its cleanup runs).
    enable_trusted_proxy_env()
    assert os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH") == "1"


def test_auth_env_is_clean_after_leak():
    # The conftest snapshot/restore must have reverted the leak from the
    # previous test, leaving a clean (open) auth env.
    assert os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH") is None
    assert os.environ.get("AGENT_BOM_TRUST_PROXY_AUTH_SECRET") is None
