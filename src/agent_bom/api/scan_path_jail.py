"""Filesystem jail for API-initiated local path scans.

API local-path scans are disabled by default. When an operator enables them,
every caller-supplied path is resolved under the configured scan root and is
rejected on traversal, symlink components, foreign ownership, or a change
between validation and open.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

from fastapi import HTTPException
from werkzeug.security import safe_join

from agent_bom.core.settings import env_first, env_flag, env_str
from agent_bom.security import SecurityError, sanitize_text

_logger = logging.getLogger(__name__)

_LOCAL_SCAN_DISABLE_VALUES = {"0", "false", "no", "off", "disabled"}


def _api_local_scans_enabled() -> bool:
    # A blank value is unset, not an opt-in: fall through to the legacy name, then disabled.
    configured = env_first("AGENT_BOM_API_LOCAL_PATH_SCANS", "AGENT_BOM_ENABLE_LOCAL_PATH_SCANS", default="disabled")
    return configured.lower() not in _LOCAL_SCAN_DISABLE_VALUES


def _api_scan_root() -> Path:
    """Return the configured API filesystem scan root.

    API-local path scans are disabled unless explicitly enabled. Workstation
    pilots can set ``AGENT_BOM_API_LOCAL_PATH_SCANS=enabled`` and optionally
    scope ``AGENT_BOM_API_SCAN_ROOT`` to a tenant workspace mount.
    """
    configured = env_str("AGENT_BOM_API_SCAN_ROOT")
    root = Path(configured).expanduser() if configured else Path.home()
    try:
        resolved = root.resolve()
    except (OSError, RuntimeError) as exc:
        raise SecurityError("Configured scan root is not available") from exc
    if not resolved.exists() or not resolved.is_dir():
        raise SecurityError("Configured scan root is not available")
    return resolved


def _enforce_api_scan_path_owner(resolved: Path, root: Path) -> None:
    """Reject paths not owned by the API process unless explicitly allowed."""
    if env_flag("AGENT_BOM_API_SCAN_ALLOW_FOREIGN_OWNER"):
        return
    if os.name == "nt":
        return
    try:
        uid = os.getuid()
        root_stat = root.stat()
        path_stat = resolved.stat()
    except OSError as exc:
        raise SecurityError("Path is not available") from exc
    if root_stat.st_uid != uid or path_stat.st_uid != uid:
        raise SecurityError("Path owner is outside the API scan boundary")


def _sanitize_api_path(user_path: str) -> str:
    """Validate and sanitize a user-supplied path from an API request.

    Interprets ``user_path`` as relative to the configured API scan root
    (absolute paths are rejected). The resolved path is normalised, has any
    symlinks resolved, and is verified to remain within the scan root
    using ``os.path.commonpath`` before being returned.
    """
    if not _api_local_scans_enabled():
        raise SecurityError("Local filesystem scans are disabled")

    # Normalise basic whitespace
    user_path = (user_path or "").strip()
    if not user_path:
        raise SecurityError("Empty paths are not allowed")

    # 1. Reject absolute paths — API callers must use paths relative to the scan root.
    if os.path.isabs(user_path):
        raise SecurityError(f"Absolute paths are not allowed: {user_path}")

    # 2. Reject path traversal in raw input (../ segments)
    if ".." in user_path.split(os.sep):
        raise SecurityError(f"Path traversal not allowed: {user_path}")

    # 3. Compute fixed root and join user path under it
    scan_root = _api_scan_root()
    root = os.path.realpath(str(scan_root))
    candidate = safe_join(root, user_path)
    if candidate is None:
        raise SecurityError("Path resolves outside configured scan root")

    # 4. Resolve to real absolute path (follows symlinks)
    try:
        resolved_path = Path(candidate).resolve(strict=True)
    except OSError as exc:
        raise SecurityError("Path does not exist inside configured scan root") from exc

    # 5. Containment check — ensure resolved path stays within the configured root.
    if os.path.commonpath([root, os.path.realpath(str(resolved_path))]) != root:
        raise SecurityError("Path resolves outside configured scan root")

    current = Path(root)
    for part in Path(user_path).parts:
        current = current / part
        try:
            if current.is_symlink():
                raise SecurityError("Symlink path components are not allowed for API local scans")
        except OSError as exc:
            raise SecurityError("Path does not exist inside configured scan root") from exc

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = -1
    try:
        fd = os.open(candidate, flags)
        opened = os.fstat(fd)
        resolved_stat = resolved_path.stat()
        if (opened.st_dev, opened.st_ino) != (resolved_stat.st_dev, resolved_stat.st_ino):
            raise SecurityError("Path changed during validation")
    except OSError as exc:
        raise SecurityError("Path cannot be opened safely inside configured scan root") from exc
    finally:
        if fd >= 0:
            os.close(fd)

    _enforce_api_scan_path_owner(resolved_path, scan_root)

    return str(resolved_path)


def _api_scan_path_or_400(user_path: str) -> str:
    try:
        return _sanitize_api_path(user_path)
    except SecurityError as exc:
        _logger.warning("blocked local API scan path: %s", sanitize_text(exc))
        if str(exc) == "Local filesystem scans are disabled":
            raise HTTPException(status_code=400, detail="Local filesystem scans are disabled") from exc
        raise HTTPException(status_code=400, detail="Invalid scan path") from exc
