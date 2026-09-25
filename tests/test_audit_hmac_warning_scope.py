"""The ephemeral audit-HMAC warning belongs to processes that sign audit evidence.

A plain ``agent-bom scan`` only *describes* signing posture in its compliance
narrative. Importing the audit module used to log the operator warning at import
time, so it landed mid-report for CLI users who never run the control plane.
"""

from __future__ import annotations

import importlib
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

WARNING_TEXT = "AGENT_BOM_AUDIT_HMAC_KEY not set"


@pytest.fixture
def fresh_audit_log(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY_FILE", raising=False)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_AUDIT_HMAC", raising=False)
    from agent_bom.api import audit_log

    module = importlib.reload(audit_log)
    yield module
    importlib.reload(audit_log)


def test_importing_and_describing_posture_does_not_warn(fresh_audit_log, caplog) -> None:
    caplog.set_level(logging.DEBUG, logger="agent_bom.api.audit_log")
    importlib.reload(fresh_audit_log)
    fresh_audit_log.describe_audit_hmac_status()
    assert WARNING_TEXT not in caplog.text


def test_first_signature_with_an_ephemeral_key_warns_once(fresh_audit_log, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="agent_bom.api.audit_log")
    first = fresh_audit_log.AuditEntry(action="scan", actor="system", resource="job/1")
    first.sign()
    second = fresh_audit_log.AuditEntry(action="scan", actor="system", resource="job/2")
    second.sign()
    assert caplog.text.count(WARNING_TEXT) == 1
    assert first.verify()


def test_api_startup_warns_about_an_ephemeral_key(fresh_audit_log, caplog) -> None:
    caplog.set_level(logging.WARNING, logger="agent_bom.api.audit_log")
    fresh_audit_log.warn_if_ephemeral_hmac_key()
    assert WARNING_TEXT in caplog.text


def test_configured_key_never_warns(monkeypatch, caplog) -> None:
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "unit-test-audit-key")
    from agent_bom.api import audit_log

    module = importlib.reload(audit_log)
    try:
        caplog.set_level(logging.WARNING, logger="agent_bom.api.audit_log")
        module.warn_if_ephemeral_hmac_key()
        module.AuditEntry(action="scan").sign()
        assert WARNING_TEXT not in caplog.text
    finally:
        monkeypatch.delenv("AGENT_BOM_AUDIT_HMAC_KEY", raising=False)
        importlib.reload(audit_log)


def test_api_lifespan_calls_the_startup_warning() -> None:
    source = (Path(__file__).resolve().parents[1] / "src/agent_bom/api/server.py").read_text(encoding="utf-8")
    lifespan = source.split("async def _lifespan(", 1)[1].split("\n    yield", 1)[0]
    assert "warn_if_ephemeral_hmac_key()" in lifespan


def test_cli_scan_output_has_no_audit_hmac_log_line(tmp_path: Path) -> None:
    home = tmp_path / "home"
    home.mkdir()
    project = tmp_path / "project"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.33.0\n", encoding="utf-8")
    env = {key: value for key, value in os.environ.items() if not key.startswith("AGENT_BOM_AUDIT_HMAC")}
    env.update({"HOME": str(home), "NO_COLOR": "1"})
    # Run the real entry point, then report whether the posture path that used to
    # trigger the import-time warning was exercised, so this cannot pass vacuously.
    driver = (
        "import sys\n"
        "from agent_bom.cli import main\n"
        "try:\n"
        "    main(sys.argv[1:])\n"
        "except SystemExit:\n"
        "    pass\n"
        "print('AUDIT_MODULE_LOADED=' + str('agent_bom.api.audit_log' in sys.modules))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", driver, "scan", str(project), "--offline"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=300,
        check=False,
    )
    combined = result.stdout + result.stderr
    assert "Offline mode" in combined, combined[-2000:]
    assert "AUDIT_MODULE_LOADED=True" in combined, combined[-2000:]
    assert WARNING_TEXT not in combined
