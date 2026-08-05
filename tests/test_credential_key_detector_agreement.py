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

Three more were found afterwards, all of them the same substring list, all of
them reporting a different number for one server: ``output.agent_mesh``'s
"N credentials" stat, the ``/agents/{name}/lifecycle`` graph's credential
nodes, and the ``agent-bom mesh`` CLI's per-server "N cred". The browser holds
one too — ``ui/lib/credential-key.ts`` is a port of the predicate, guarded by
``ui/tests/credential-key.test.ts`` against these same fixture names.

``enforcement.check_claude_config`` holds a fourth copy and is deliberately
left alone: its question is "does this env var hold an inline *secret*", and
the canonical name list is too broad to raise a high-severity finding from —
it would report ``CERTIFICATE_PATH=/etc/ssl/ca.pem`` as a hardcoded secret.
"""

from __future__ import annotations

import ast
import asyncio
from typing import Any

import pytest

from agent_bom.ai_components.framework_agents import _extract_credential_refs
from agent_bom.cli.agents._posture import render_posture_summary
from agent_bom.constants import is_credential_key
from agent_bom.models import Agent, AgentType, BlastRadius, MCPServer, Package, Severity, Vulnerability
from agent_bom.output.agent_mesh import build_agent_mesh
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
    # Consolidating four detectors onto one predicate narrowed it past the
    # point of correctness: these are the canonical names of real credentials
    # and every one of them dropped out of inventory, graph and posture.
    # Plural forms are the largest family — a name is no less a credential for
    # holding more than one.
    "GOOGLE_APPLICATION_CREDENTIALS": "abc",
    "PGPASSWORD": "abc",
    "ID_RSA": "abc",
    "CERTIFICATE": "abc",
    "OAUTH": "abc",
    "API_KEYS": "abc",
    "SSH_KEYS": "abc",
    "CREDENTIALS": "abc",
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
    # The precision half of the pair above. An earlier attempt to restore the
    # missing names widened the predicate until these came back as credentials,
    # and was reverted for it: a certificate is public material and a pool size
    # is a number. Restoring coverage must not re-buy that over-claim, so both
    # directions are asserted together.
    "CERT_FILE": "/etc/ssl/certs/ca-bundle.crt",
    "OAUTH_CLIENT_ID": "0oa1b2c3d4",
    "OAUTH_ENABLED": "true",
    "CREDENTIAL_ROTATION_POLICY": "90d",
    "API_KEYS_ENABLED": "true",
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


def _mixed_env() -> dict[str, str]:
    return {**CREDENTIAL_ENV, **NON_CREDENTIAL_ENV, **CREDENTIAL_ADJACENT_CONFIG_ENV}


def test_agent_mesh_credential_count_uses_the_canonical_predicate() -> None:
    """The mesh's "N credentials" stat is the same claim the graph export makes.

    Two surfaces reading the same server reported different totals, because the
    mesh kept its own substring list: ``KEYBOARD_LAYOUT`` and ``AUTH_MODE``
    became credentials there and nowhere else.
    """
    server = {"name": "warehouse", "packages": [], "tools": [], "env": _mixed_env()}
    agents = [{"name": "a1", "agent_type": "test", "mcp_servers": [server]}]

    mesh = build_agent_mesh(agents)

    assert mesh["stats"]["total_credentials"] == len(CREDENTIAL_ENV)
    assert mesh["stats"]["total_credentials"] == len(_credential_names_from_server(server))


def test_mesh_cli_credential_count_uses_the_canonical_predicate(capsys: pytest.CaptureFixture[str]) -> None:
    """The CLI prints "N cred" per server beside the same mesh stats."""
    from rich.console import Console

    from agent_bom.cli._analysis import _render_mesh_summary

    server = {"name": "warehouse", "packages": [], "tools": [], "env": _mixed_env()}
    agents = [{"name": "a1", "agent_type": "test", "mcp_servers": [server]}]

    _render_mesh_summary(Console(width=200), agents, build_agent_mesh(agents), scope_label="local", quiet=True)

    assert f"{len(CREDENTIAL_ENV)} cred" in " ".join(capsys.readouterr().out.split())


def test_agent_lifecycle_credential_nodes_use_the_canonical_predicate(monkeypatch: pytest.MonkeyPatch) -> None:
    """Credential nodes in the lifecycle graph are the third copy of the judgement."""
    from agent_bom.api.routes import discovery

    server = {"name": "warehouse", "packages": [], "tools": [], "env": _mixed_env()}

    async def _fake_detail(request: Any, agent_name: str) -> dict[str, Any]:
        return {
            "agent": {"name": agent_name, "agent_type": "test", "mcp_servers": [server]},
            "summary": {},
        }

    monkeypatch.setattr(discovery, "get_agent_detail", _fake_detail)

    graph = asyncio.run(discovery.get_agent_lifecycle(None, "a1"))  # type: ignore[arg-type]
    labels = sorted(node["data"]["label"] for node in graph["nodes"] if node["data"]["nodeType"] == "credential")

    assert labels == sorted(CREDENTIAL_ENV)


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
