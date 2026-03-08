"""Tests for process and container MCP server discovery.

Both discovery functions are purely opt-in and degrade gracefully when
their dependencies (psutil / docker CLI) are absent.  All tests mock
external dependencies so the suite runs in CI without psutil installed
or Docker running.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agent_bom.discovery import discover_container_labels, discover_running_processes
from agent_bom.models import AgentType, TransportType

# ─── discover_running_processes ───────────────────────────────────────────────


def _make_proc(pid: int, cmdline: list[str], environ: dict | None = None, cwd: str = "/tmp") -> MagicMock:
    """Build a mock psutil.Process with the given attributes."""
    proc = MagicMock()
    proc.info = {
        "pid": pid,
        "name": cmdline[0].rsplit("/", 1)[-1] if cmdline else "",
        "cmdline": cmdline,
        "environ": environ or {},
        "cwd": cwd,
    }
    return proc


def test_returns_none_when_psutil_not_installed():
    """Graceful fallback when psutil is not installed."""
    with patch.dict("sys.modules", {"psutil": None}):
        # Re-import to trigger the ImportError path
        import importlib

        import agent_bom.discovery as disc

        importlib.reload(disc)
        result = disc.discover_running_processes()

    assert result is None


def test_returns_none_when_no_mcp_processes():
    """No MCP processes → None (not an empty Agent)."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(1001, ["python", "my_script.py"]),
        _make_proc(1002, ["node", "app.js"]),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        result = discover_running_processes()

    assert result is None


def test_detects_npx_modelcontextprotocol_process():
    """npx @modelcontextprotocol/server-filesystem detected as MCP server."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(
            2001,
            ["node", "/usr/local/lib/node_modules/npx", "@modelcontextprotocol/server-filesystem", "/home/user/docs"],
        ),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    assert len(agent.mcp_servers) == 1
    assert agent.source == "process"
    assert agent.agent_type == AgentType.CUSTOM
    assert "modelcontextprotocol" in agent.mcp_servers[0].name.lower() or "server-filesystem" in agent.mcp_servers[0].name.lower()


def test_detects_uvx_mcp_server_process():
    """uvx mcp-server-fetch detected."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(3001, ["uvx", "mcp-server-fetch"]),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    assert len(agent.mcp_servers) >= 1
    assert agent.mcp_servers[0].command == "uvx"


def test_detects_mcp_server_in_name():
    """Process with mcp-server in its executable name is detected."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(4001, ["/usr/local/bin/mcp-server", "--transport", "sse", "--port", "8080"]),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    srv = agent.mcp_servers[0]
    assert srv.transport == TransportType.SSE


def test_skips_inaccessible_processes():
    """Processes raising AccessDenied are silently skipped."""
    mock_psutil = MagicMock()
    bad_proc = MagicMock()
    bad_proc.info = {"pid": 9999, "name": "denied", "cmdline": None, "environ": {}, "cwd": None}

    good_proc = _make_proc(5001, ["node", "@modelcontextprotocol/server-filesystem"])
    mock_psutil.process_iter.return_value = [bad_proc, good_proc]
    mock_psutil.NoSuchProcess = ProcessLookupError
    mock_psutil.AccessDenied = PermissionError
    mock_psutil.ZombieProcess = ChildProcessError

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    # Should still find the good process
    assert agent is not None


def test_sse_transport_detected_from_args():
    """--transport sse in process args sets transport to SSE."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(6001, ["uvx", "mcp-server-fetch", "--transport", "sse"]),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    assert agent.mcp_servers[0].transport == TransportType.SSE


def test_env_vars_are_sanitized():
    """Credential env vars in process environment are sanitized (value redacted)."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(7001, ["uvx", "mcp-server-fetch"], environ={"API_KEY": "super-secret", "HOME": "/home/user"}),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    env = agent.mcp_servers[0].env
    assert env.get("API_KEY") != "super-secret"  # must be redacted


def test_process_config_path_contains_pid():
    """config_path for process-discovered servers contains the PID."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(8001, ["node", "@modelcontextprotocol/server-filesystem"]),
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    assert "8001" in agent.mcp_servers[0].config_path


def test_multiple_mcp_processes_all_captured():
    """Multiple MCP processes result in multiple MCPServer entries."""
    mock_psutil = MagicMock()
    mock_psutil.process_iter.return_value = [
        _make_proc(9001, ["node", "@modelcontextprotocol/server-filesystem"]),
        _make_proc(9002, ["uvx", "mcp-server-fetch"]),
        _make_proc(9003, ["python", "my_script.py"]),  # not MCP
    ]
    mock_psutil.NoSuchProcess = Exception
    mock_psutil.AccessDenied = Exception
    mock_psutil.ZombieProcess = Exception

    with patch.dict("sys.modules", {"psutil": mock_psutil}):
        agent = discover_running_processes()

    assert agent is not None
    assert len(agent.mcp_servers) == 2


# ─── discover_container_labels ────────────────────────────────────────────────


def _docker_inspect_json(
    cid: str,
    image: str,
    labels: dict | None = None,
    env: list[str] | None = None,
    cmd: list[str] | None = None,
    ports: dict | None = None,
) -> str:
    """Build a minimal docker inspect JSON payload."""
    return json.dumps(
        {
            "Id": cid,
            "Config": {
                "Image": image,
                "Labels": labels or {},
                "Env": env or [],
                "Cmd": cmd or [],
                "Entrypoint": [],
            },
            "NetworkSettings": {"Ports": ports or {}},
        }
    )


def _run_side_effects(ps_stdout: str, inspect_outputs: list[str]):
    """Build side_effect list for subprocess.run mocks."""

    def _side_effect(cmd, **kwargs):
        mock_result = MagicMock()
        if cmd[0] == "docker" and cmd[1] == "ps":
            mock_result.returncode = 0
            mock_result.stdout = ps_stdout
        elif cmd[0] == "docker" and cmd[1] == "inspect":
            if inspect_outputs:
                mock_result.returncode = 0
                mock_result.stdout = inspect_outputs.pop(0)
            else:
                mock_result.returncode = 1
                mock_result.stdout = ""
        return mock_result

    return _side_effect


def test_container_returns_none_when_docker_not_installed():
    """Returns None when docker is not on PATH."""
    with patch("shutil.which", return_value=None):
        result = discover_container_labels()
    assert result is None


def test_container_returns_none_when_no_containers_running():
    """Returns None when docker ps returns an empty list."""
    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        result = discover_container_labels()
    assert result is None


def test_container_returns_none_when_docker_ps_fails():
    """Returns None when docker ps exits non-zero."""
    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("subprocess.run") as mock_run,
    ):
        mock_run.return_value = MagicMock(returncode=1, stdout="")
        result = discover_container_labels()
    assert result is None


def test_container_detects_mcp_image_name():
    """Container with 'mcp-server' in image name is detected."""
    cid = "abc123def456"
    inspect_json = _docker_inspect_json(cid, "ghcr.io/modelcontextprotocol/mcp-server-fetch:latest")

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    assert len(agent.mcp_servers) == 1
    assert agent.source == "container"
    assert agent.agent_type == AgentType.CUSTOM


def test_container_detects_mcp_label():
    """Container with mcp label is detected even without mcp in image name."""
    cid = "bcd234eff567"
    inspect_json = _docker_inspect_json(
        cid,
        "my-custom-server:1.0",
        labels={"mcp.name": "my-custom-server", "version": "1.0"},
    )

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    assert agent.mcp_servers[0].name == "my-custom-server"


def test_container_detects_mcp_env_var():
    """Container with MCP_SERVER env var is detected."""
    cid = "cde345f00678"
    inspect_json = _docker_inspect_json(
        cid,
        "custom-server:2.0",
        env=["MCP_SERVER_PORT=3000", "HOME=/root"],
    )

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    assert len(agent.mcp_servers) == 1


def test_container_skips_non_mcp_containers():
    """Containers with no MCP signals are excluded."""
    cid = "def456a00789"
    inspect_json = _docker_inspect_json(cid, "nginx:latest", env=["NGINX_PORT=80"])

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        result = discover_container_labels()

    assert result is None


def test_container_sse_transport_when_ports_exposed():
    """Container with exposed ports gets SSE transport."""
    cid = "f00123abc456"
    inspect_json = _docker_inspect_json(
        cid,
        "mcp-server-custom:1.0",
        ports={"3000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "3000"}]},
    )

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    srv = agent.mcp_servers[0]
    assert srv.transport == TransportType.SSE
    assert srv.url == "http://localhost:3000"


def test_container_env_vars_are_sanitized():
    """Sensitive env vars in containers are sanitized."""
    cid = "a1b2c3d4e5f6"
    inspect_json = _docker_inspect_json(
        cid,
        "mcp-server-fetch:latest",
        env=["OPENAI_API_KEY=sk-secret123", "MCP_PORT=8080"],
    )

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = cid + "\n"
        else:
            m.returncode = 0
            m.stdout = inspect_json
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    env = agent.mcp_servers[0].env
    assert env.get("OPENAI_API_KEY") != "sk-secret123"


def test_container_multiple_mcp_containers():
    """Multiple MCP containers each become separate MCPServer entries."""
    ids = ["aaa111", "bbb222"]
    inspect_outputs = [
        _docker_inspect_json("aaa111", "mcp-server-fetch:latest"),
        _docker_inspect_json("bbb222", "mcp-server-filesystem:latest"),
    ]

    call_count = {"inspect": 0}

    def _side_effect(cmd, **kwargs):
        m = MagicMock()
        if cmd[1] == "ps":
            m.returncode = 0
            m.stdout = "\n".join(ids) + "\n"
        else:
            m.returncode = 0
            idx = call_count["inspect"]
            m.stdout = inspect_outputs[idx] if idx < len(inspect_outputs) else "{}"
            call_count["inspect"] += 1
        return m

    with (
        patch("shutil.which", return_value="/usr/bin/docker"),
        patch("agent_bom.discovery.subprocess.run", side_effect=_side_effect),
    ):
        agent = discover_container_labels()

    assert agent is not None
    assert len(agent.mcp_servers) == 2


# ─── discover_all integration ─────────────────────────────────────────────────


def test_discover_all_skips_processes_by_default():
    """discover_all does NOT call process discovery unless include_processes=True."""
    with (
        patch("agent_bom.discovery.discover_global_configs", return_value=[]),
        patch("agent_bom.discovery.discover_project_configs", return_value=[]),
        patch("agent_bom.discovery.discover_compose_mcp_servers", return_value=None),
        patch("agent_bom.discovery.discover_toolhive", return_value=None),
        patch("agent_bom.discovery.discover_docker_mcp", return_value=None),
        patch("agent_bom.discovery.detect_installed_agents", return_value=[]),
        patch("agent_bom.discovery.discover_running_processes") as mock_proc,
        patch("agent_bom.discovery.discover_container_labels") as mock_cont,
    ):
        from agent_bom.discovery import discover_all

        discover_all()

    mock_proc.assert_not_called()
    mock_cont.assert_not_called()


def test_discover_all_calls_process_discovery_when_flagged():
    """discover_all calls discover_running_processes when include_processes=True."""
    with (
        patch("agent_bom.discovery.discover_global_configs", return_value=[]),
        patch("agent_bom.discovery.discover_project_configs", return_value=[]),
        patch("agent_bom.discovery.discover_compose_mcp_servers", return_value=None),
        patch("agent_bom.discovery.discover_toolhive", return_value=None),
        patch("agent_bom.discovery.discover_docker_mcp", return_value=None),
        patch("agent_bom.discovery.detect_installed_agents", return_value=[]),
        patch("agent_bom.discovery.discover_running_processes", return_value=None) as mock_proc,
        patch("agent_bom.discovery.discover_container_labels", return_value=None),
    ):
        from agent_bom.discovery import discover_all

        discover_all(include_processes=True)

    mock_proc.assert_called_once()


def test_discover_all_calls_container_discovery_when_flagged():
    """discover_all calls discover_container_labels when include_containers=True."""
    with (
        patch("agent_bom.discovery.discover_global_configs", return_value=[]),
        patch("agent_bom.discovery.discover_project_configs", return_value=[]),
        patch("agent_bom.discovery.discover_compose_mcp_servers", return_value=None),
        patch("agent_bom.discovery.discover_toolhive", return_value=None),
        patch("agent_bom.discovery.discover_docker_mcp", return_value=None),
        patch("agent_bom.discovery.detect_installed_agents", return_value=[]),
        patch("agent_bom.discovery.discover_running_processes", return_value=None),
        patch("agent_bom.discovery.discover_container_labels", return_value=None) as mock_cont,
    ):
        from agent_bom.discovery import discover_all

        discover_all(include_containers=True)

    mock_cont.assert_called_once()
