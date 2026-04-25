"""agent-bom run — launch an MCP server through the runtime proxy.

Zero-config shorthand for ``agent-bom proxy``.  Resolves common server
prefixes (npx/, uvx/, ghcr.io/, docker/) into the correct subprocess
command, then delegates to the existing :func:`agent_bom.proxy.run_proxy`
async loop which handles all stdio bridging, policy enforcement, rate
limiting, and audit logging.
"""

from __future__ import annotations

import asyncio
import logging
import shlex
import sys

import click

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Server-spec prefix resolution
# ---------------------------------------------------------------------------

# Launcher prefixes: strip prefix, pass remainder as args to the launcher binary.
_LAUNCHER_PREFIXES: dict[str, list[str]] = {
    "npx/": ["npx", "--yes"],
    "uvx/": ["uvx"],
    "uvx:": ["uvx"],
}

# Docker shorthand prefix: "docker/" → "docker run --rm -i <remainder>".
_DOCKER_SHORTHAND = "docker/"

# Registry prefixes: the entire spec (including prefix) is the image reference.
_REGISTRY_PREFIXES: tuple[str, ...] = ("ghcr.io/", "docker.io/")


def _resolve_server_command(server: str) -> list[str]:
    """Resolve a server spec string to a subprocess command list.

    Three resolution strategies, in priority order:

    1. **Registry prefix** (``ghcr.io/``, ``docker.io/``): the full spec
       string is the Docker image reference — ``docker run --rm -i <spec>``.
    2. **Docker shorthand** (``docker/``): ``docker run --rm -i`` followed
       by the remainder after the prefix.
    3. **Launcher prefix** (``npx/``, ``uvx/``, ``uvx:``): the launcher
       binary is prepended and the remainder (after stripping the prefix)
       is split as shell tokens.
    4. **Plain command**: the entire string is split with :func:`shlex.split`.

    Examples::

        "npx/@modelcontextprotocol/server-filesystem /tmp"
            -> ["npx", "--yes", "@modelcontextprotocol/server-filesystem", "/tmp"]

        "uvx/mcp-server-git"
            -> ["uvx", "mcp-server-git"]

        "ghcr.io/owner/image:tag"
            -> ["docker", "run", "--rm", "-i", "ghcr.io/owner/image:tag"]

        "docker.io/library/alpine:3.20"
            -> ["docker", "run", "--rm", "-i", "docker.io/library/alpine:3.20"]

        "docker/myorg/myimage:latest"
            -> ["docker", "run", "--rm", "-i", "myorg/myimage:latest"]

        "python -m my_server"
            -> ["python", "-m", "my_server"]
    """
    # Registry prefixes — keep the full image reference intact.
    for prefix in _REGISTRY_PREFIXES:
        if server.startswith(prefix):
            image, *extra = server.split(" ", 1)
            extra_args = shlex.split(extra[0]) if extra else []
            return ["docker", "run", "--rm", "-i", image] + extra_args

    # Docker shorthand — strip "docker/" then treat remainder as image + args.
    if server.startswith(_DOCKER_SHORTHAND):
        parts = shlex.split(server[len(_DOCKER_SHORTHAND) :])
        return ["docker", "run", "--rm", "-i"] + parts

    # Launcher prefixes — strip prefix, split remainder as shell tokens.
    for prefix, cmd_prefix in _LAUNCHER_PREFIXES.items():
        if server.startswith(prefix):
            remainder = server[len(prefix) :]
            return cmd_prefix + shlex.split(remainder)

    # Default: treat the whole string as a shell command.
    return shlex.split(server)


# ---------------------------------------------------------------------------
# Click command
# ---------------------------------------------------------------------------


@click.command("run")
@click.argument("server")
@click.option(
    "--policy",
    "-p",
    default=None,
    metavar="FILE",
    type=click.Path(exists=True),
    help="Policy file (JSON) to enforce at runtime.",
)
@click.option(
    "--rate-limit",
    default=0,
    show_default=True,
    metavar="N",
    help="Max MCP tool calls per tool per 60 s (0 = unlimited).",
)
@click.option(
    "--audit-log",
    default=None,
    metavar="FILE",
    help="Write JSONL audit log to FILE.",
)
@click.option(
    "--block-undeclared",
    is_flag=True,
    help="Block tool calls that were not in the initial tools/list response.",
)
@click.option(
    "--detect-credentials",
    is_flag=True,
    help="Detect credential leaks in tool responses.",
)
@click.option(
    "--detect-visual-leaks",
    is_flag=True,
    help="OCR-scan image tool responses for credentials/PII (requires 'agent-bom[visual]').",
)
@click.option(
    "--log-only",
    is_flag=True,
    help="Log alerts without blocking (advisory mode).",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress agent-bom startup messages.",
)
@click.option(
    "--isolate/--no-isolate",
    default=False,
    envvar="AGENT_BOM_MCP_SANDBOX",
    help="Run the MCP server through a hardened Docker/Podman container.",
)
@click.option(
    "--sandbox-runtime",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_RUNTIME",
    type=click.Choice(["auto", "docker", "podman"]),
    help="Container runtime for --isolate (default: auto).",
)
@click.option(
    "--sandbox-image",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_IMAGE",
    help="Container image used to run non-container server commands in --isolate mode.",
)
@click.option(
    "--sandbox-mount",
    multiple=True,
    metavar="HOST:CONTAINER[:ro|rw]",
    help="Explicit bind mount for --isolate. Defaults to read-only.",
)
@click.option("--sandbox-cpus", default=None, envvar="AGENT_BOM_MCP_SANDBOX_CPUS", help="CPU limit for isolated MCP server.")
@click.option("--sandbox-memory", default=None, envvar="AGENT_BOM_MCP_SANDBOX_MEMORY", help="Memory limit for isolated MCP server.")
@click.option(
    "--sandbox-pids-limit",
    default=None,
    type=int,
    envvar="AGENT_BOM_MCP_SANDBOX_PIDS_LIMIT",
    help="Process limit for isolated MCP server.",
)
@click.option(
    "--sandbox-tmpfs-size",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_TMPFS_SIZE",
    help="Writable /tmp tmpfs size for isolated MCP server, for example 64m.",
)
@click.option(
    "--sandbox-timeout-seconds",
    default=None,
    type=int,
    envvar="AGENT_BOM_MCP_SANDBOX_TIMEOUT_SECONDS",
    help="Optional max runtime before the isolated MCP server is terminated.",
)
@click.option(
    "--sandbox-egress",
    default=None,
    envvar="AGENT_BOM_MCP_SANDBOX_EGRESS",
    type=click.Choice(["deny", "allow-all"]),
    help="Network egress posture for isolated MCP server.",
)
@click.pass_context
def run_cmd(
    ctx: click.Context,
    server: str,
    policy: str | None,
    rate_limit: int,
    audit_log: str | None,
    block_undeclared: bool,
    detect_credentials: bool,
    detect_visual_leaks: bool,
    log_only: bool,
    quiet: bool,
    isolate: bool,
    sandbox_runtime: str | None,
    sandbox_image: str | None,
    sandbox_mount: tuple[str, ...],
    sandbox_cpus: str | None,
    sandbox_memory: str | None,
    sandbox_pids_limit: int | None,
    sandbox_tmpfs_size: str | None,
    sandbox_timeout_seconds: int | None,
    sandbox_egress: str | None,
) -> None:
    """Launch SERVER through agent-bom's runtime proxy.

    SERVER can be any of the following forms:

    \b
      npx/@modelcontextprotocol/server-filesystem /path
      uvx/mcp-server-git
      ghcr.io/owner/image:tag
      docker.io/owner/image:tag
      python -m my_mcp_server
      /usr/local/bin/my-server --arg

    \b
    The proxy intercepts all MCP JSON-RPC traffic, enforces policy,
    and optionally writes an audit log.  Rate limiting and credential-
    leak detection are available as flags.

    \b
    Examples:

    \b
      agent-bom run "npx/@modelcontextprotocol/server-filesystem /tmp"
      agent-bom run "uvx/mcp-server-git" --policy ./policy.json
      agent-bom run "ghcr.io/msaad00/agent-bom:latest" --audit-log audit.jsonl
      agent-bom run "python -m myserver" --rate-limit 30 --detect-credentials
    """
    from agent_bom.project_config import get_policy_path, load_project_config
    from agent_bom.proxy import run_proxy
    from agent_bom.proxy_sandbox import sandbox_config_from_env

    # Auto-load .agent-bom.yaml policy if --policy not explicitly given
    if not policy:
        _cfg = load_project_config()
        if _cfg and (cfg_policy := get_policy_path(_cfg)):
            policy = str(cfg_policy)

    cmd = _resolve_server_command(server)

    if not cmd:
        click.echo("Error: server spec is empty or invalid.", err=True)
        ctx.exit(1)
        return

    if not quiet:
        click.echo(
            f"agent-bom: launching {cmd[0]!r} through runtime proxy",
            err=True,
        )
        if policy:
            click.echo(f"agent-bom: policy: {policy}", err=True)
        if isolate:
            click.echo("agent-bom: MCP container isolation enabled", err=True)

    try:
        sandbox_config = sandbox_config_from_env(
            enabled=isolate,
            runtime=sandbox_runtime,
            image=sandbox_image,
            mounts=sandbox_mount,
            cpus=sandbox_cpus,
            memory=sandbox_memory,
            pids_limit=sandbox_pids_limit,
            tmpfs_size=sandbox_tmpfs_size,
            timeout_seconds=sandbox_timeout_seconds,
            egress_policy=sandbox_egress,
        )
    except ValueError as exc:
        raise click.UsageError(str(exc)) from exc

    # Build env for child process — no mutation of current env needed here;
    # run_proxy spawns the subprocess itself and inherits os.environ.
    exit_code = asyncio.run(
        run_proxy(
            server_cmd=cmd,
            policy_path=policy,
            log_path=audit_log,
            block_undeclared=block_undeclared,
            detect_credentials=detect_credentials,
            detect_visual_leaks=detect_visual_leaks,
            rate_limit_threshold=rate_limit,
            log_only=log_only,
            sandbox_config=sandbox_config,
        )
    )
    sys.exit(exit_code)
