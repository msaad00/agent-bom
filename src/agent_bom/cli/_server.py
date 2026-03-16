"""Server commands — REST API, MCP server, combined serve."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click


@click.command("serve")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to (use 0.0.0.0 for LAN access)")
@click.option("--port", default=8422, show_default=True, help="API server port")
@click.option("--persist", default=None, metavar="DB_PATH", help="Enable persistent job storage via SQLite (e.g. --persist jobs.db).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def serve_cmd(host: str, port: int, persist: Optional[str], cors_allow_all: bool, reload: bool, log_level: str, log_json: bool):
    """Start the API server + Next.js dashboard.

    \b
    Requires:  pip install 'agent-bom[ui]'

    \b
    Usage:
      agent-bom serve
      agent-bom serve --port 8422 --persist jobs.db
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        click.echo(
            "ERROR: FastAPI + Uvicorn are required for `agent-bom serve`.\nInstall them with:  pip install 'agent-bom[ui]'",
            err=True,
        )
        sys.exit(1)

    import os as _os

    if persist:
        _os.environ["AGENT_BOM_DB"] = str(Path(persist).resolve())
    if cors_allow_all:
        _os.environ["AGENT_BOM_CORS_ALL"] = "1"

    _ui_dist = Path(__file__).parent / "ui_dist"
    click.echo(f"\n  API server  →  http://{host}:{port}")
    click.echo(f"  API docs    →  http://{host}:{port}/docs")
    if (_ui_dist / "index.html").exists():
        click.echo(f"  Dashboard   →  http://{host}:{port}")
    else:
        click.echo("  Dashboard   →  not bundled (run: make build-ui)")
    click.echo("  Press Ctrl+C to stop.\n")

    import uvicorn as _uvicorn

    _uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        timeout_keep_alive=5,
        limit_concurrency=500,
    )


@click.command("api")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host to bind to (use 0.0.0.0 for LAN access)")
@click.option("--port", default=8422, show_default=True, help="Port to listen on")
@click.option("--reload", is_flag=True, help="Auto-reload on code changes (development mode)")
@click.option("--workers", default=1, show_default=True, help="Number of worker processes")
@click.option("--cors-origins", default=None, metavar="ORIGINS", help="Comma-separated CORS origins (default: localhost:3000).")
@click.option("--cors-allow-all", is_flag=True, default=False, help="Allow all CORS origins (dev mode).")
@click.option(
    "--api-key", default=None, envvar="AGENT_BOM_API_KEY", metavar="KEY", help="Require API key auth (Bearer token or X-API-Key header)."
)
@click.option(
    "--rate-limit",
    "rate_limit_rpm",
    default=60,
    show_default=True,
    type=int,
    metavar="RPM",
    help="Rate limit for scan endpoints (requests/minute per IP).",
)
@click.option(
    "--persist",
    default=None,
    metavar="DB_PATH",
    help="Enable persistent job storage via SQLite (e.g. --persist jobs.db). Jobs survive restarts.",
)
@click.option(
    "--log-level",
    "log_level",
    type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Log verbosity level.",
)
@click.option("--log-json", "log_json", is_flag=True, help="Emit structured JSON logs (for log aggregation pipelines).")
def api_cmd(
    host: str,
    port: int,
    reload: bool,
    workers: int,
    cors_origins: str | None,
    cors_allow_all: bool,
    api_key: str | None,
    rate_limit_rpm: int,
    persist: str | None,
    log_level: str,
    log_json: bool,
):
    """Start the agent-bom REST API server.

    \b
    Requires:  pip install 'agent-bom[api]'

    \b
    Endpoints:
      GET  /docs                   Interactive API docs (Swagger UI)
      GET  /health                 Liveness probe
      GET  /version                Version info
      POST /v1/scan                Start a scan (async, returns job_id)
      GET  /v1/scan/{job_id}       Poll status + results
      GET  /v1/scan/{job_id}/stream  SSE real-time progress
      GET  /v1/agents              Quick agent discovery (no CVE scan)
      GET  /v1/jobs                List all scan jobs

    \b
    Usage:
      agent-bom api                           # local dev: http://127.0.0.1:8422
      agent-bom api --host 0.0.0.0            # expose on LAN
      agent-bom api --port 9000               # custom port
      agent-bom api --reload                  # dev mode
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        import uvicorn
    except ImportError:
        click.echo(
            "ERROR: uvicorn is required for `agent-bom api`.\nInstall it with:  pip install 'agent-bom[api]'",
            err=True,
        )
        sys.exit(1)

    import os as _os

    from agent_bom import __version__ as _ver
    from agent_bom.api.server import configure_api, set_job_store

    origins = cors_origins.split(",") if cors_origins else None
    configure_api(
        cors_origins=origins,
        cors_allow_all=cors_allow_all,
        api_key=api_key,
        rate_limit_rpm=rate_limit_rpm,
    )

    pg_url = _os.environ.get("AGENT_BOM_POSTGRES_URL")
    if pg_url and not persist:
        # Postgres takes priority when no explicit --persist flag
        from agent_bom.api.postgres_store import PostgresJobStore

        set_job_store(PostgresJobStore())
    elif persist:
        from agent_bom.api.store import SQLiteJobStore

        set_job_store(SQLiteJobStore(db_path=persist))

    click.echo(f"  agent-bom API v{_ver}")
    click.echo(f"  Listening on http://{host}:{port}")
    click.echo(f"  Docs:         http://{host}:{port}/docs")
    if api_key:
        click.echo("  Auth:         API key required (Bearer / X-API-Key)")
    if pg_url and not persist:
        click.echo("  Storage:      PostgreSQL")
    elif persist:
        click.echo(f"  Storage:      SQLite ({persist})")
    click.echo("  Press Ctrl+C to stop.\n")

    uvicorn.run(
        "agent_bom.api.server:app",
        host=host,
        port=port,
        reload=reload,
        workers=1 if reload else workers,
        log_level=log_level.lower(),
        # Slowloris / connection-exhaustion hardening:
        # Close idle keep-alive connections after 5s (uvicorn default is 5s but
        # we set it explicitly so it's visible and auditable).
        timeout_keep_alive=5,
        # Hard cap on concurrent in-flight requests; prevents thread/FD exhaustion
        # under a slow-connection flood. 500 ≫ any realistic single-server load.
        limit_concurrency=500,
    )


@click.command("mcp-server")
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="stdio",
    show_default=True,
    help="MCP transport protocol.",
)
@click.option("--port", default=8423, show_default=True, help="Port for HTTP/SSE transport.")
@click.option("--host", default="127.0.0.1", show_default=True, help="Host for HTTP/SSE transport.")
@click.option("--log-level", "log_level", type=click.Choice(["DEBUG", "INFO", "WARNING", "ERROR"], case_sensitive=False), default="INFO")
@click.option("--log-json", "log_json", is_flag=True, help="Structured JSON logs")
def mcp_server_cmd(transport: str, port: int, host: str, log_level: str, log_json: bool):
    """Start agent-bom as an MCP server.

    \b
    Requires:  pip install 'agent-bom[mcp-server]'

    \b
    Exposes 32 security tools via MCP protocol:
      scan                   Full scan — CVEs, config security, blast radius, compliance
      check                  Check a specific package for CVEs before installing
      blast_radius           Look up blast radius for a specific CVE
      policy_check           Evaluate policy rules against scan findings
      registry_lookup        Query MCP server security metadata registry
      generate_sbom          Generate CycloneDX or SPDX SBOM
      compliance             14-framework compliance posture
      remediate              Generate actionable remediation plan
      skill_trust            Trust assessment for SKILL.md files
      verify                 Package integrity + SLSA provenance verification
      where                  Show all MCP discovery paths + existence status
      inventory              List agents/servers without CVE scanning
      diff                   Compare scan against baseline for new/resolved vulns
      marketplace_check      Pre-install marketplace trust check
      code_scan              SAST scanning via Semgrep with CWE mapping
      context_graph          Agent context graph with lateral movement analysis
      analytics_query        Query vulnerability trends from ClickHouse
      cis_benchmark          Run CIS benchmark checks (AWS/Snowflake)
      fleet_scan             Batch registry lookup for fleet inventories
      runtime_correlate      Cross-reference runtime logs with CVE findings
      vector_db_scan         Discover vector databases and assess auth exposure
      aisvs_benchmark        OWASP AISVS v1.0 compliance checks
      gpu_infra_scan         GPU container and K8s node inventory + DCGM probe
      ai_inventory_scan      Detect AI SDK imports, shadow AI, deprecated models
      browser_extension_scan Audit browser extensions for AI/MCP capabilities
      dataset_card_scan      Scan dataset cards for license and provenance
      ingest_external_scan   Import Trivy/Grype/Syft scan results
      license_compliance_scan License risk detection for dependencies
      model_file_scan        Scan ML model files for security risks
      model_provenance_scan  Verify model origin and supply chain integrity
      prompt_scan            Detect prompt injection patterns
      training_pipeline_scan Audit ML training pipeline configurations

    \b
    Usage:
      agent-bom mcp-server                                # stdio (Claude Desktop, Cursor)
      agent-bom mcp-server --transport sse                # SSE (remote clients)
      agent-bom mcp-server --transport streamable-http    # Streamable HTTP (Smithery, etc.)

    \b
    Claude Desktop config (~/.claude/claude_desktop_config.json):
      {"mcpServers": {"agent-bom": {"command": "agent-bom", "args": ["mcp-server"]}}}
    """
    from agent_bom.logging_config import setup_logging

    setup_logging(level=log_level, json_output=log_json)

    try:
        from agent_bom.mcp_server import create_mcp_server
    except ImportError:
        click.echo(
            "ERROR: mcp SDK is required for `agent-bom mcp-server`.\nInstall it with:  pip install 'agent-bom[mcp-server]'",
            err=True,
        )
        sys.exit(1)

    server = create_mcp_server(host=host, port=port)

    if transport in ("sse", "streamable-http"):
        from agent_bom import __version__ as _ver

        click.echo(f"  agent-bom MCP Server v{_ver}", err=True)
        click.echo(f"  Transport: {transport} on http://{host}:{port}", err=True)
        click.echo("  Press Ctrl+C to stop.\n", err=True)
        server.run(transport=transport)
    else:
        server.run(transport="stdio")
