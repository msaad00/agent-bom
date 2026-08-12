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


def test_exit_code_contract_documents_connect_failure_codes() -> None:
    """`connect` must never exit 0 on failure, and the doc must say which code it uses.

    The codes the CLI actually emits are asserted against the doc so the two
    cannot drift — a reserved code (`3`/`4`/`5`) must not sneak in here.
    """
    from agent_bom.cli._entry_points import _EXIT_OPERATIONAL, _EXIT_USAGE, _USAGE_STATUSES

    assert (_EXIT_OPERATIONAL, _EXIT_USAGE) == (1, 2)
    assert _USAGE_STATUSES == frozenset({400, 422})

    text = EXIT_CODES_DOC.read_text(encoding="utf-8")
    assert "`agent-bom connect <provider>` failing to verify or register" in text
    assert "exits `2` when the control plane\nrejects the payload and `1` for every other failure" in text
    assert "never exits `0` without a verified connection" in text


def test_action_exposes_documented_exit_code_output() -> None:
    action = ACTION_YML.read_text(encoding="utf-8")
    doc = EXIT_CODES_DOC.read_text(encoding="utf-8")

    assert "exit-code:" in action
    assert "value: ${{ steps.scan.outputs.exit_code }}" in action
    assert "| `exit-code`" in doc


def test_first_run_guide_covers_the_exit_codes_and_ci_use_readme_promises() -> None:
    """A reader must reach the exit-code contract from the README and from the guide.

    The README used to promise this only in passing, inside the first-run-guide
    link ("for exit codes, formats, and CI use"), which meant a first-time user
    met a red `Exiting with code 1` before meeting any explanation of it. It now
    states the contract at the front door and links the canonical reference
    directly, so that link is what this guards. The guide must still reach the
    same reference rather than dead-ending at the demo's status `1`, and both
    link it instead of restating the table, so the three cannot drift.
    """
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "site-docs/reference/exit-codes.md" in readme
    assert "[first-run guide](docs/FIRST_RUN.md)" in readme
    # The front door must say what a non-zero exit means, not just link it.
    assert "non-zero exit is a verdict, not a crash" in readme.lower()

    guide = (ROOT / "docs" / "FIRST_RUN.md").read_text(encoding="utf-8")
    assert "../site-docs/reference/exit-codes.md" in guide
    assert "--fail-on-severity" in guide
    assert "--fail-on-kev" in guide

    # Every GitHub Action input the guide shows must really exist in action.yml.
    action = ACTION_YML.read_text(encoding="utf-8")
    for action_input in ("severity-threshold", "warn-on-severity", "format"):
        assert f"\n  {action_input}:\n" in action, action_input
        assert f"{action_input}:" in guide, action_input
