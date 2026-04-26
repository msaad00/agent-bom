from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXIT_CODES_DOC = ROOT / "site-docs" / "reference" / "exit-codes.md"
ACTION_YML = ROOT / "action.yml"


def test_exit_code_contract_documents_required_cli_codes() -> None:
    text = EXIT_CODES_DOC.read_text(encoding="utf-8")

    for code in ("`0`", "`1`", "`2`", "`3`", "`4`", "`5`", "`130`"):
        assert code in text
    assert "subprocess passthrough" in text
    assert "ok, findings, usage, auth, and server failures" in text


def test_exit_code_contract_maps_http_statuses_to_cli_families() -> None:
    text = EXIT_CODES_DOC.read_text(encoding="utf-8")

    expected_mappings = {
        "`0`": "`2xx`",
        "`2`": "`400` `422`",
        "`4` (reserved)": "`401` `403`",
        "`1`": "`404` `409`",
        "`5` (reserved)": "`5xx`",
    }
    for cli_code, http_status in expected_mappings.items():
        assert cli_code in text
        assert http_status in text


def test_action_exposes_documented_exit_code_output() -> None:
    action = ACTION_YML.read_text(encoding="utf-8")
    doc = EXIT_CODES_DOC.read_text(encoding="utf-8")

    assert "exit-code:" in action
    assert "value: ${{ steps.scan.outputs.exit_code }}" in action
    assert "| `exit-code`" in doc
