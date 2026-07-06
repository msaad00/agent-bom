from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
INSTALL_SH = ROOT / "scripts" / "deploy" / "install.sh"


def test_deploy_install_script_is_valid_shell() -> None:
    subprocess.run(["bash", "-n", str(INSTALL_SH)], check=True)


def test_deploy_install_script_list_documents_targets() -> None:
    proc = subprocess.run(
        ["bash", str(INSTALL_SH), "list"],
        check=True,
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    output = proc.stdout
    for token in ("pilot", "eks", "connect aws", "snowflake", "onboard"):
        assert token in output, f"missing target hint: {token}"


def test_deploy_quickstart_doc_exists() -> None:
    doc = ROOT / "docs" / "DEPLOY_QUICKSTART.md"
    text = doc.read_text(encoding="utf-8")
    assert "scripts/deploy/install.sh" in text
    assert "read-only" in text.lower()


def test_deploy_runbook_exists() -> None:
    runbook = ROOT / "deploy" / "RUNBOOK.md"
    text = runbook.read_text(encoding="utf-8")
    assert "Cross-cloud federation" in text
    assert "multicloud-collector-values.yaml" in text
