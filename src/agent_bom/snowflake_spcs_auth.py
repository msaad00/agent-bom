"""Snowpark Container Services workload-identity connection parameters.

Snowflake injects account, host, database, schema, and a rotating OAuth token
file into every service container. Native App workloads must use that identity
instead of browser, password, or key-pair credentials.
"""

from __future__ import annotations

import os
from typing import Any

_NATIVE_APP_ENV = "AGENT_BOM_SNOWFLAKE_NATIVE_APP"
_DEFAULT_TOKEN_FILE = "/snowflake/session/token"
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def native_app_mode() -> bool:
    """Return whether the process runs inside the Snowflake Native App."""

    return os.environ.get(_NATIVE_APP_ENV, "").strip().lower() in _TRUTHY


def apply_spcs_workload_identity(params: dict[str, Any]) -> bool:
    """Replace external credentials with SPCS OAuth workload identity.

    Returns ``False`` outside Native App mode. In Native App mode the injected
    account context is required and any caller-provided long-lived credential is
    removed. ``token_file_path`` lets the connector read the rotating token for
    every new connection instead of caching token contents in process memory.
    """

    if not native_app_mode():
        return False

    required = {
        "account": os.environ.get("SNOWFLAKE_ACCOUNT", "").strip(),
        "host": os.environ.get("SNOWFLAKE_HOST", "").strip(),
    }
    missing = [name.upper() for name, value in required.items() if not value]
    if missing:
        raise RuntimeError(f"SPCS workload identity is missing injected Snowflake context: {', '.join(missing)}")

    for key in (
        "user",
        "password",
        "private_key",
        "private_key_file",
        "private_key_file_pwd",
        "token",
    ):
        params.pop(key, None)
    params.update(required)
    params["authenticator"] = "oauth"
    params["token_file_path"] = os.environ.get("SNOWFLAKE_TOKEN_FILE_PATH", _DEFAULT_TOKEN_FILE).strip() or _DEFAULT_TOKEN_FILE
    return True


__all__ = ["apply_spcs_workload_identity", "native_app_mode"]
