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


def test_first_run_guide_covers_the_exit_codes_and_ci_use_readme_promises() -> None:
    """README sends readers to the first-run guide "for exit codes, formats, and CI use".

    The guide must therefore actually reach that contract instead of dead-ending
    at the demo's status `1`. It links the canonical reference rather than
    restating the table, so the two can never drift.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "[first-run guide](docs/FIRST_RUN.md) for exit codes" in readme

    guide = (ROOT / "docs" / "FIRST_RUN.md").read_text(encoding="utf-8")
    assert "../site-docs/reference/exit-codes.md" in guide
    assert "--fail-on-severity" in guide
    assert "--fail-on-kev" in guide

    # Every GitHub Action input the guide shows must really exist in action.yml.
    action = ACTION_YML.read_text(encoding="utf-8")
    for action_input in ("severity-threshold", "warn-on-severity", "format"):
        assert f"\n  {action_input}:\n" in action, action_input
        assert f"{action_input}:" in guide, action_input
