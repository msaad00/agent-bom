"""``scan(package=...)`` must never report a clean result it did not earn.

``_package_spec_agent`` forced every unrecognized launcher token to ``npx``, so
a PyPI requirement was scanned as an npm package:

    scan(package="flask==0.12.2")     -> npx ['flask==0.12.2'] | 0 packages | 0 CVEs
    scan(package="uvx flask==0.12.2") -> uvx ['flask==0.12.2'] | flask@0.12.2 | 4 CVEs
    check(package="flask==0.12.2", ecosystem="pypi") -> vulnerable, 4 CVEs

The first call extracted nothing, emitted no warning, and was presented as a
completed AI-BOM — a silent wrong answer for an agent asking "is this safe to
install".  The same forcing mis-attributed ``pip install flask==0.12.2`` to an
npm package named ``pip`` and ``uv tool run flask==0.12.2`` to a PyPI package
named ``run``.

These tests lock three properties:

1. a bare PyPI requirement resolves to the PyPI package it names;
2. an explicit ``ecosystem`` wins over any launcher guess; and
3. fail-closed — a package spec that yields zero packages is reported as an
   incomplete scan with a warning, never as a clean AI-BOM.
"""

from __future__ import annotations

import json

import pytest

from agent_bom.mcp_server_scan import _package_spec_agent
from agent_bom.parsers import extract_packages


def _extracted(spec: str, *, ecosystem: str | None = None) -> tuple[list[tuple[str, str, str]], list[str]]:
    agent, warnings = _package_spec_agent(spec, ecosystem=ecosystem)
    server = agent.mcp_servers[0]
    packages = server.packages or extract_packages(server)
    return [(p.name, p.version, p.ecosystem) for p in packages], warnings


def _trunc(text: str) -> str:
    return text


# ── 1. Ecosystem resolution ──────────────────────────────────────────────────


def test_bare_pypi_requirement_resolves_to_pypi() -> None:
    """`flask==0.12.2` is a PyPI requirement, not an npm package name."""
    packages, _warnings = _extracted("flask==0.12.2")
    assert packages == [("flask", "0.12.2", "pypi")]


def test_bare_pypi_requirement_matches_the_uvx_prefixed_form() -> None:
    """The only difference between the two spellings must be the spelling."""
    bare, _ = _extracted("flask==0.12.2")
    prefixed, _ = _extracted("uvx flask==0.12.2")
    assert bare == prefixed


def test_pip_install_spec_resolves_the_installed_package_not_pip() -> None:
    packages, _warnings = _extracted("pip install flask==0.12.2")
    assert packages == [("flask", "0.12.2", "pypi")]


def test_uv_tool_run_spec_resolves_the_tool_not_the_subcommand() -> None:
    packages, _warnings = _extracted("uv tool run flask==0.12.2")
    assert packages == [("flask", "0.12.2", "pypi")]


def test_uv_launcher_config_resolves_the_tool_not_the_subcommand() -> None:
    """Same defect class in the shared extractor a real MCP config goes through.

    ``{"command": "uv", "args": ["tool", "run", "flask==0.12.2"]}`` resolved to a
    PyPI package literally named ``run`` because the token after the first
    sub-command was read as the package.
    """
    from agent_bom.models import MCPServer, TransportType

    server = MCPServer(
        name="uv-tool-run",
        command="uv",
        args=["tool", "run", "flask==0.12.2"],
        transport=TransportType.STDIO,
        config_path="/tmp/uv.json",
    )
    packages = [(p.name, p.version, p.ecosystem) for p in extract_packages(server)]
    assert packages == [("flask", "0.12.2", "pypi")]


def test_npm_launcher_behaviour_is_unchanged() -> None:
    packages, warnings = _extracted("npx left-pad@1.0.0")
    assert packages == [("left-pad", "1.0.0", "npm")]
    assert warnings == [], "an explicit launcher is not a guess and must not warn"


# ── 2. Explicit ecosystem wins ───────────────────────────────────────────────


@pytest.mark.parametrize(
    ("spec", "ecosystem", "expected"),
    [
        ("serde@1.0.0", "cargo", ("serde", "1.0.0", "cargo")),
        ("flask==0.12.2", "pypi", ("flask", "0.12.2", "pypi")),
        ("left-pad@1.0.0", "npm", ("left-pad", "1.0.0", "npm")),
        ("github.com/gin-gonic/gin@1.9.0", "go", ("github.com/gin-gonic/gin", "1.9.0", "go")),
    ],
)
def test_explicit_ecosystem_overrides_the_launcher_guess(spec: str, ecosystem: str, expected: tuple[str, str, str]) -> None:
    packages, warnings = _extracted(spec, ecosystem=ecosystem)
    assert packages == [expected]
    assert warnings == [], "an explicit ecosystem is not a guess and must not warn"


def test_ambiguous_spec_declares_the_assumed_ecosystem() -> None:
    """`name@version` is genuinely ambiguous; the assumption must be stated."""
    packages, warnings = _extracted("serde@1.0.0")
    assert packages == [("serde", "1.0.0", "npm")]
    assert warnings, "an inferred ecosystem must be surfaced, not silently applied"
    joined = " ".join(warnings).lower()
    assert "npm" in joined
    assert "ecosystem" in joined


def test_invalid_ecosystem_is_rejected() -> None:
    with pytest.raises(ValueError):
        _package_spec_agent("flask==0.12.2", ecosystem="not-a-real-ecosystem")


# ── 3. Fail closed: zero packages is never a clean scan ──────────────────────


@pytest.mark.asyncio
async def test_package_spec_yielding_no_packages_is_reported_incomplete() -> None:
    """A package spec the extractor cannot resolve must not read as clean."""
    from agent_bom.mcp_tools.scanning import scan_impl

    async def _pipeline(*_args, **_kwargs):
        agent, _warnings = _package_spec_agent("totally::unparseable::spec")
        for server in agent.mcp_servers:
            server.packages = []
        return [agent], [], [], ["mcp_package"]

    payload = json.loads(
        await scan_impl(
            package="totally::unparseable::spec",
            offline=True,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    )

    assert payload.get("status") == "incomplete_scan", f"zero-package scan presented as complete: status={payload.get('status')!r}"
    warnings = " ".join(payload.get("warnings") or []).lower()
    assert "no packages" in warnings or "could not" in warnings, payload.get("warnings")


@pytest.mark.asyncio
async def test_resolved_package_spec_is_still_a_normal_scan() -> None:
    """The fail-closed guard must not fire when the spec really did resolve."""
    from agent_bom.mcp_tools.scanning import scan_impl

    async def _pipeline(*_args, **_kwargs):
        agent, _warnings = _package_spec_agent("flask==0.12.2")
        for server in agent.mcp_servers:
            if not server.packages:
                server.packages = extract_packages(server)
        return [agent], [], [], ["mcp_package"]

    payload = json.loads(
        await scan_impl(
            package="flask==0.12.2",
            offline=True,
            _run_scan_pipeline=_pipeline,
            _truncate_response=_trunc,
        )
    )

    assert payload.get("status") != "incomplete_scan"
    assert payload.get("document_type") == "AI-BOM"


@pytest.mark.asyncio
async def test_scan_tool_accepts_an_ecosystem_argument() -> None:
    """The wrong-ecosystem trap is only closable if the caller can be explicit."""
    import inspect

    from agent_bom.mcp_tools.scanning import scan_impl

    assert "ecosystem" in inspect.signature(scan_impl).parameters

    captured: dict[str, object] = {}

    async def _pipeline(*args, **kwargs):
        captured.update(kwargs)
        agent, _warnings = _package_spec_agent("serde@1.0.0", ecosystem="cargo")
        return [agent], [], [], ["mcp_package"]

    await scan_impl(
        package="serde@1.0.0",
        ecosystem="cargo",
        offline=True,
        _run_scan_pipeline=_pipeline,
        _truncate_response=_trunc,
    )
    assert captured.get("ecosystem") == "cargo"
