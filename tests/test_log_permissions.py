"""Test that security-sensitive files get 0o600 permissions."""

import os
import tempfile


def test_log_file_permissions():
    from agent_bom.logging_config import setup_logging

    with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
        path = f.name
    try:
        setup_logging(log_file=path)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
    finally:
        os.unlink(path)


def test_audit_db_permissions():
    from agent_bom.api.audit_log import SQLiteAuditLog

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        path = f.name
    try:
        SQLiteAuditLog(db_path=path)
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"Expected 0o600, got {oct(mode)}"
    finally:
        os.unlink(path)
