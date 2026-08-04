"""One question — "is this env-var name a credential?" — had four answers.

``constants.is_credential_key`` is the canonical predicate: it decides
``MCPServer.credential_names``, which in turn drives blast-radius
``exposed_credentials``, the graph's credential nodes and the compliance
controls that key off them.  Three other modules re-implemented the same
judgement with shorter literal lists, and they disagreed with it:

* ``security.sanitize_env_vars`` left the *value* of a variable in cleartext
  that the very same report lists as an exposed credential;
* ``ai_components.framework_agents`` dropped ``PASSWORD``/``DATABASE_URL``
  refs from framework-native agents;
* the ``--posture`` panel's "N with credentials" count contradicted the
  "N cred(s) reachable" line printed six rows below it.

``enforcement.check_claude_config`` holds a fourth copy and is deliberately
left alone: its question is "does this env var hold an inline *secret*", and
the canonical name list is too broad to raise a high-severity finding from —
it would report ``CERTIFICATE_PATH=/etc/ssl/ca.pem`` as a hardcoded secret.
"""

from __future__ import annotations

import ast

import pytest

from agent_bom.ai_components.framework_agents import _extract_credential_refs
from agent_bom.cli.agents._posture import render_posture_summary
from agent_bom.constants import is_credential_key
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.graph_export import _credential_names_from_server
from agent_bom.security import sanitize_env_vars

# Env-var names taken from published MCP server and agent-framework setups.
# Values are deliberately short and low-entropy so the value-based and
# entropy-based redaction fallbacks cannot rescue a key-name miss.
CREDENTIAL_ENV: dict[str, str] = {
    "GITHUB_TOKEN": "abc",
    "OPENAI_API_KEY": "abc",
    "NEO4J_PASSWORD": "abc",
    "DATABASE_URL": "abc",
    "SSH_KEY": "abc",
    "ENCRYPTION_KEY": "abc",
    "AUTHORIZATION": "abc",
    "CLIENT_SECRET": "abc",
    "CA_CERT": "abc",
    "AWS_ACCESS_KEY_ID": "abc",
    "AZURE_CLIENT_CERTIFICATE_PATH": "/run/secrets/azure-client.pem",
    "AZURE_STORAGE_CONNECTION_STRING": "abc",
    "SNOWFLAKE_PRIVATE_KEY_PATH": "/run/secrets/snowflake-key.pem",
}

NON_CREDENTIAL_ENV: dict[str, str] = {
    "PATH": "/usr/bin",
    "HOME": "/root",
    "LOG_LEVEL": "debug",
    "PORT": "8080",
    "NODE_ENV": "production",
    "ALLOWED_DIRECTORIES": "/srv/data",
}

CREDENTIAL_ADJACENT_CONFIG_ENV: dict[str, str] = {
    # Operational settings that contain credential-adjacent substrings are
    # configuration, not authentication material.  Counting them as exposed
    # credentials inflates graph, posture, and blast-radius evidence.
    "AUTH_MODE": "oauth",
    "CERTIFICATE_PATH": "/etc/ssl/certs/ca-bundle.crt",
    "DB_CONNECTION_POOL_SIZE": "20",
    "KEYBOARD_LAYOUT": "us",
    "AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS": "3600",
    "AGENT_BOM_AZURE_AUTHORIZATION_MAX_RECORDS": "500",
    "AGENT_BOM_MCP_AUTH_REQUIRE_NETWORK_AUTH": "true",
    "AGENT_BOM_TLS_REQUIRE_CLIENT_CERT": "true",
    "AGENT_BOM_TOKEN_ROTATION_DAYS": "30",
}


def test_fixture_names_match_the_canonical_predicate() -> None:
    """Guard the fixtures themselves, so a drifting canonical list is visible here."""
    assert [name for name in CREDENTIAL_ENV if not is_credential_key(name)] == []
    non_credentials = {**NON_CREDENTIAL_ENV, **CREDENTIAL_ADJACENT_CONFIG_ENV}
    assert [name for name in non_credentials if is_credential_key(name)] == []


def test_mcp_server_credential_inventory_uses_the_canonical_predicate() -> None:
    """The model must not bypass the predicate used by graph consumers."""
    server = MCPServer(
        name="warehouse",
        env={**CREDENTIAL_ENV, **NON_CREDENTIAL_ENV, **CREDENTIAL_ADJACENT_CONFIG_ENV},
    )

    assert sorted(server.credential_names) == sorted(CREDENTIAL_ENV)
    assert server.has_credentials

    config_only = MCPServer(name="warehouse", env=dict(CREDENTIAL_ADJACENT_CONFIG_ENV))
    assert config_only.credential_names == []
    assert not config_only.has_credentials


def test_legacy_graph_export_fallback_uses_the_canonical_predicate() -> None:
    """Legacy scan JSON must not reintroduce a second credential judgement."""
    env = {**CREDENTIAL_ENV, **NON_CREDENTIAL_ENV, **CREDENTIAL_ADJACENT_CONFIG_ENV}

    assert _credential_names_from_server({"env": env}) == sorted(CREDENTIAL_ENV)


@pytest.mark.parametrize("name", sorted(CREDENTIAL_ENV))
def test_credential_values_are_redacted(name: str) -> None:
    """A name the product reports as a credential must have its value redacted."""
    assert sanitize_env_vars({name: CREDENTIAL_ENV[name]})[name] == "***REDACTED***"


@pytest.mark.parametrize("name", sorted(NON_CREDENTIAL_ENV))
def test_non_credential_values_survive_redaction(name: str) -> None:
    assert sanitize_env_vars({name: NON_CREDENTIAL_ENV[name]})[name] == NON_CREDENTIAL_ENV[name]


def test_framework_agent_credential_refs_match_the_canonical_predicate() -> None:
    """``_extract_credential_refs`` is the same judgement over Python source."""
    reads = "\n".join(f'{name.lower()} = os.getenv("{name}")' for name in CREDENTIAL_ENV)
    non_credentials = {**NON_CREDENTIAL_ENV, **CREDENTIAL_ADJACENT_CONFIG_ENV}
    reads += "\n" + "\n".join(f'{name.lower()}_2 = os.environ["{name}"]' for name in non_credentials)
    source = f"import os\nfrom crewai import Agent\n\n{reads}\n"

    assert sorted(_extract_credential_refs(ast.parse(source))) == sorted(CREDENTIAL_ENV)


def _agent_with_env(env: dict[str, str]) -> tuple[list[Agent], list[BlastRadius]]:
    vuln = Vulnerability(id="GHSA-0000-0000-0001", summary="rce", severity=Severity.HIGH, cvss_score=8.1)
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi", vulnerabilities=[vuln], is_direct=True)
    server = MCPServer(name="warehouse", env=dict(env), packages=[pkg])
    agent = Agent(
        name="claude-desktop",
        agent_type=AgentType.CLAUDE_DESKTOP,
        config_path="/tmp/claude.json",
        mcp_servers=[server],
    )
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=server.credential_names,
        exposed_tools=[],
    )
    br.calculate_risk_score()
    return [agent], [br]


def test_posture_credential_server_count_agrees_with_reachable_creds(capsys: pytest.CaptureFixture[str]) -> None:
    """Both numbers are printed in one panel; they must come from one predicate."""
    agents, blast_radii = _agent_with_env({"DATABASE_URL": "***REDACTED***"})

    render_posture_summary(agents, blast_radii)

    flat = " ".join(capsys.readouterr().out.split())
    assert "1 MCP servers (1 with credentials)" in flat
    assert "1 cred(s)" in flat
