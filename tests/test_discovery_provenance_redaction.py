"""Discovery provenance markers are paths, not secrets.

``MCPServer.discovery_sources`` holds ``<source>:<location>`` markers such as
``project-config:/tmp/abom/73694/proj/.mcp.json``. Digit runs in the directory
part used to push the whole marker over the entropy threshold, so ordinary
provenance was exported as ``***REDACTED***`` for some directory names and not
others. These tests sweep digit runs, keep real secrets redacted, and pin the
unchanged behaviour of ``sanitize_env_vars`` for string env values.
"""

from __future__ import annotations

import base64

import pytest

from agent_bom.models import Agent, AgentType, AIBOMReport, MCPServer
from agent_bom.output.json_fmt import to_redacted_json
from agent_bom.security import sanitize_env_vars, sanitize_sensitive_payload

REDACTED = "***REDACTED***"
_DIGIT_RUNS = range(10000, 100000, 37)
_ROOTS = ("/private/tmp/abom/{n}", "/private/tmp/abom-scan-{n}-project_fail_on_low", "/Users/dev{n}/work/proj{n}")

# Split so secret scanners do not flag the fixtures themselves.
_OPENAI_SHAPED = "sk-" + "proj-" + "Zq8Xv2Lm4Np6Rt0Bw3Ky7Hd1Fs5Gj9Ca"
_GITHUB_SHAPED = "gh" + "p_" + "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dE3fG5"


def _sanitized_source(marker: str) -> str:
    result = sanitize_sensitive_payload({"discovery_sources": [marker]})
    assert isinstance(result, dict)
    return result["discovery_sources"][0]


@pytest.mark.parametrize("root", _ROOTS)
def test_provenance_paths_with_digit_runs_are_never_fully_redacted(root: str) -> None:
    for n in _DIGIT_RUNS:
        marker = f"project-config:{root.format(n=n)}/.mcp.json"
        assert _sanitized_source(marker) == "project-config:<path:.mcp.json>", marker


def test_provenance_path_is_labelled_like_every_other_exported_path() -> None:
    assert _sanitized_source("claude-desktop:/Users/alice/Library/Application Support/Claude/claude_desktop_config.json") == (
        "claude-desktop:<path:claude_desktop_config.json>"
    )
    assert _sanitized_source("cursor:C:\\Users\\alice\\.cursor\\mcp.json") == "cursor:<path:mcp.json>"
    assert _sanitized_source("project-config:<path:.mcp.json>") == "project-config:<path:.mcp.json>"


def test_non_path_provenance_markers_are_unchanged() -> None:
    assert _sanitized_source("mcp_scan_package") == "mcp_scan_package"
    assert _sanitized_source("process:pid:42") == "process:pid:42"
    assert _sanitized_source("cortex-code:cortex-code") == "cortex-code:cortex-code"


def test_json_report_keeps_discovery_provenance_for_digit_run_directories() -> None:
    marker = "project-config:/private/tmp/abom-scan-73694-project_fail_on_low/proj/.mcp.json"
    server = MCPServer(name="filesystem", command="npx", discovery_sources=[marker])
    agent = Agent(name="project:proj", agent_type=AgentType.CUSTOM, config_path="/private/tmp/proj", mcp_servers=[server])
    report = to_redacted_json(AIBOMReport(agents=[agent]))
    assert report["agents"][0]["mcp_servers"][0]["discovery_sources"] == ["project-config:<path:.mcp.json>"]


@pytest.mark.parametrize(
    ("marker", "secret"),
    [
        (f"project-config:/home/alice/{_OPENAI_SHAPED}/.mcp.json", _OPENAI_SHAPED),
        (f"project-config:/home/alice/proj/{_OPENAI_SHAPED}", _OPENAI_SHAPED),
        (f"{_OPENAI_SHAPED}:/home/alice/proj/.mcp.json", _OPENAI_SHAPED),
        (f"remote:https://mcp.example.com/sse?token={_GITHUB_SHAPED}", _GITHUB_SHAPED),
        (f"remote:https://alice:{_GITHUB_SHAPED}@mcp.example.com/sse", _GITHUB_SHAPED),
        (f"env:{_GITHUB_SHAPED}", _GITHUB_SHAPED),
    ],
)
def test_real_secret_inside_provenance_is_still_redacted(marker: str, secret: str) -> None:
    assert secret not in _sanitized_source(marker)


@pytest.mark.parametrize("n", [73694, 72552])
def test_sanitize_env_vars_list_repro_is_not_redacted(n: int) -> None:
    value = [f"project-config:/private/tmp/abom/{n}/proj/.mcp.json"]
    assert sanitize_env_vars({"k": value}) == {"k": str(value)}


def test_sanitize_env_vars_never_redacts_the_repro_path_family() -> None:
    for n in _DIGIT_RUNS:
        value = [f"project-config:/private/tmp/abom/{n}/proj/.mcp.json"]
        assert sanitize_env_vars({"k": value}) == {"k": str(value)}, value


@pytest.mark.parametrize("root", _ROOTS)
def test_sanitize_env_vars_judges_a_list_by_its_elements_not_its_repr(root: str) -> None:
    for n in _DIGIT_RUNS:
        element = f"project-config:{root.format(n=n)}/.mcp.json"
        element_redacted = sanitize_env_vars({"k": element})["k"] == REDACTED
        expected = REDACTED if element_redacted else str([element])
        assert sanitize_env_vars({"k": [element]})["k"] == expected, element


@pytest.mark.parametrize(
    "value",
    [
        ["ok", _OPENAI_SHAPED],
        (_GITHUB_SHAPED,),
        {"nested": [_GITHUB_SHAPED]},
        {"API_TOKEN": "short"},
    ],
)
def test_sanitize_env_vars_still_redacts_containers_holding_secrets(value: object) -> None:
    assert sanitize_env_vars({"CUSTOM": value}) == {"CUSTOM": REDACTED}


_HIGH_ENTROPY = "Xk9#mQ2$vL7@pR4!tW8&nB3*zF6^hJ1%cD5(gS0)yU"
_ENCODED_PASSWORD = base64.b64encode(b"password=correct-horse-battery-staple").decode()


@pytest.mark.parametrize(
    ("key", "value", "expected"),
    [
        ("API_TOKEN", "anything", REDACTED),
        ("DB_PASSWORD", "", REDACTED),
        ("CUSTOM", _GITHUB_SHAPED, REDACTED),
        ("CUSTOM", _OPENAI_SHAPED, REDACTED),
        ("CUSTOM", _HIGH_ENTROPY, REDACTED),
        ("CUSTOM", _ENCODED_PASSWORD, REDACTED),
        # A string env value is judged as a whole, exactly as before.
        ("CUSTOM", "['project-config:/private/tmp/abom/73694/proj/.mcp.json']", REDACTED),
        ("CUSTOM", "production", "production"),
        ("CUSTOM", "/usr/local/bin", "/usr/local/bin"),
        ("CUSTOM", "https://example.com/mcp", "https://example.com/mcp"),
        ("PORT", 8080, "8080"),
        ("DEBUG", True, "True"),
        ("EMPTY", None, "None"),
    ],
)
def test_sanitize_env_vars_scalar_values_behave_as_before(key: str, value: object, expected: str) -> None:
    assert sanitize_env_vars({key: value}) == {key: expected}


def test_sanitize_env_vars_fails_closed_on_deeply_nested_containers() -> None:
    value: object = "plain"
    for _ in range(12):
        value = [value]
    assert sanitize_env_vars({"CUSTOM": value}) == {"CUSTOM": REDACTED}
