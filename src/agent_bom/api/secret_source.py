"""Resolve control-plane secrets from mounted files or process env.

Compose / local stacks should mount secrets as files (Docker secrets) and set
``AGENT_BOM_<NAME>_FILE``. Helm may still inject via Secret→env; plain env
remains accepted so existing clusters do not break.

``*_FILE`` always wins when set. Values are never logged.
"""

from __future__ import annotations

import os
from pathlib import Path


def resolve_secret(env_name: str, *, required: bool = False) -> str:
    """Return the secret for ``env_name`` from ``{env_name}_FILE`` or env.

    Parameters
    ----------
    env_name:
        Base environment variable (e.g. ``AGENT_BOM_API_KEY``).
    required:
        When True, raise ``ValueError`` if neither file nor env yields a value.

    Raises
    ------
    ValueError
        Missing/empty file when ``*_FILE`` is set, or required secret absent.
    """
    file_env = f"{env_name}_FILE"
    file_path = os.environ.get(file_env, "").strip()
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            raise ValueError(f"{file_env} not found: {file_path}")
        value = path.read_text(encoding="utf-8").strip("\r\n")
        if not value:
            raise ValueError(f"{file_env} is empty: {file_path}")
        return value

    value = (os.environ.get(env_name) or "").strip()
    if required and not value:
        raise ValueError(f"{env_name} or {file_env} is required")
    return value


def secret_is_configured(env_name: str) -> bool:
    """Return True when a non-empty secret is available via file or env.

    When ``*_FILE`` is set, the path must exist and contain non-empty content.
    Does not raise on a missing file path (callers that need fail-closed should
    use :func:`resolve_secret`).
    """
    file_env = f"{env_name}_FILE"
    file_path = os.environ.get(file_env, "").strip()
    if file_path:
        path = Path(file_path)
        if not path.is_file():
            return False
        try:
            return bool(path.read_text(encoding="utf-8").strip("\r\n"))
        except OSError:
            return False
    return bool((os.environ.get(env_name) or "").strip())
