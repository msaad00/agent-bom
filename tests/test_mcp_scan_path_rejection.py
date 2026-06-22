"""Regression: an out-of-sandbox scan path must raise a clean validation error.

Previously run_scan_pipeline returned a single mcp_error_json string on a
rejected path, but its ~11 call-sites unpack a 4-tuple — so a path outside the
sandbox crashed with "too many values to unpack (expected 4)" (and several
tools masked it as isError:false). It now raises McpScanValidationError so every
caller surfaces a clean, structured error.
"""

import asyncio

import pytest

from agent_bom.mcp_server_scan import (
    CODE_VALIDATION_INVALID_PATH,
    McpScanValidationError,
    run_scan_pipeline,
)


def _reject_path(_p):
    raise ValueError("path is outside home directory")


def test_out_of_sandbox_config_path_raises_clean_validation_error():
    with pytest.raises(McpScanValidationError) as exc_info:
        asyncio.run(run_scan_pipeline(safe_path=_reject_path, config_path="/etc/passwd"))
    err = exc_info.value
    assert err.code == CODE_VALIDATION_INVALID_PATH
    assert err.argument == "config_path"
    # The message is clean and structured — never the unpack crash.
    assert "too many values to unpack" not in str(err)
    assert CODE_VALIDATION_INVALID_PATH in str(err)


def test_validation_error_is_a_valueerror_for_existing_handlers():
    # Subclasses ValueError so tools' existing except-handlers still catch it.
    assert issubclass(McpScanValidationError, ValueError)
