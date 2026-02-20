"""Tests for cloud provider auto-discovery and graph output."""

import importlib
import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cloud import CloudDiscoveryError, discover_from_provider
from agent_bom.cloud.base import CloudDiscoveryError as BaseCloudError
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────

def _install_mock_boto3():
    """Install a mock boto3/botocore in sys.modules so we can patch it.

    Returns the SAME module objects on repeated calls so exception classes
    match across test functions.
    """
    if "botocore.exceptions" in sys.modules and hasattr(sys.modules["botocore.exceptions"], "NoCredentialsError"):
        botocore_exc = sys.modules["botocore.exceptions"]
        boto3 = sys.modules["boto3"]
        return boto3, botocore_exc

    botocore = types.ModuleType("botocore")
    botocore_exc = types.ModuleType("botocore.exceptions")

    class _NoCredentialsError(Exception):
        pass

    class _ClientError(Exception):
        def __init__(self, error_response, operation_name):
            self.response = error_response
            self.operation_name = operation_name
            msg = error_response.get("Error", {}).get("Message", "")
            super().__init__(msg)

    botocore_exc.NoCredentialsError = _NoCredentialsError
    botocore_exc.ClientError = _ClientError
    botocore.exceptions = botocore_exc

    boto3 = types.ModuleType("boto3")
    boto3.Session = MagicMock

    sys.modules["botocore"] = botocore
    sys.modules["botocore.exceptions"] = botocore_exc
    sys.modules["boto3"] = boto3

    return boto3, botocore_exc


def _install_mock_databricks():
    """Install a mock databricks-sdk in sys.modules."""
    databricks = types.ModuleType("databricks")
    databricks_sdk = types.ModuleType("databricks.sdk")
    databricks_sdk_errors = types.ModuleType("databricks.sdk.errors")

    class _PermissionDeniedError(Exception):
        pass

    databricks_sdk_errors.PermissionDenied = _PermissionDeniedError
    databricks_sdk.WorkspaceClient = MagicMock
    databricks_sdk.errors = databricks_sdk_errors
    databricks.sdk = databricks_sdk

    sys.modules.setdefault("databricks", databricks)
    sys.modules.setdefault("databricks.sdk", databricks_sdk)
    sys.modules.setdefault("databricks.sdk.errors", databricks_sdk_errors)

    return databricks_sdk


def _install_mock_snowflake():
    """Install a mock snowflake-connector-python in sys.modules."""
    snowflake = types.ModuleType("snowflake")
    snowflake_connector = types.ModuleType("snowflake.connector")
    snowflake_connector_errors = types.ModuleType("snowflake.connector.errors")

    class _DatabaseError(Exception):
        pass

    snowflake_connector_errors.DatabaseError = _DatabaseError
    snowflake_connector.connect = MagicMock
    snowflake_connector.errors = snowflake_connector_errors
    snowflake.connector = snowflake_connector

    sys.modules.setdefault("snowflake", snowflake)
    sys.modules.setdefault("snowflake.connector", snowflake_connector)
    sys.modules.setdefault("snowflake.connector.errors", snowflake_connector_errors)

    return snowflake_connector


# ─── Cloud Aggregator Tests ──────────────────────────────────────────────────


def test_discover_from_provider_unknown():
    """Unknown provider raises ValueError with available provider list."""
    with pytest.raises(ValueError, match="Unknown cloud provider"):
        discover_from_provider("oracle")


def test_cloud_discovery_error_is_base():
    """CloudDiscoveryError imported from __init__ and base are the same."""
    assert CloudDiscoveryError is BaseCloudError


# ─── AWS Provider Tests ──────────────────────────────────────────────────────


def test_aws_missing_boto3():
    """Helpful error when boto3 is not installed."""
    with patch.dict(sys.modules, {"boto3": None, "botocore": None, "botocore.exceptions": None}):
        import agent_bom.cloud.aws as aws_mod
        try:
            importlib.reload(aws_mod)
        except Exception:
            pass
        with pytest.raises(CloudDiscoveryError, match="boto3 is required"):
            from agent_bom.cloud.aws import discover
            discover()


def test_aws_bedrock_agents_discovered():
    """Bedrock agents are converted to Agent objects with correct ARN."""
    mock_boto3, _ = _install_mock_boto3()

    mock_session = MagicMock()
    mock_bedrock = MagicMock()

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [
        {"agentSummaries": [
            {"agentId": "ABC123", "agentName": "prod-agent", "agentStatus": "PREPARED"}
        ]}
    ]
    mock_ag_paginator = MagicMock()
    mock_ag_paginator.paginate.return_value = [{"actionGroupSummaries": []}]

    mock_bedrock.get_paginator.side_effect = lambda op: {
        "list_agents": mock_paginator,
        "list_agent_action_groups": mock_ag_paginator,
    }[op]
    mock_bedrock.get_agent.return_value = {
        "agent": {
            "agentId": "ABC123", "agentName": "prod-agent",
            "agentArn": "arn:aws:bedrock:us-east-1:123456:agent/ABC123",
            "foundationModel": "anthropic.claude-3-sonnet", "agentStatus": "PREPARED",
        }
    }

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]
    mock_session.region_name = "us-east-1"

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1")

    assert len(agents) >= 1
    bedrock_agents = [a for a in agents if a.source == "aws-bedrock"]
    assert len(bedrock_agents) == 1
    assert bedrock_agents[0].name == "bedrock:prod-agent"
    assert "arn:aws:bedrock" in bedrock_agents[0].config_path
    assert bedrock_agents[0].agent_type == AgentType.CUSTOM


def test_aws_no_credentials_returns_warning():
    """NoCredentialsError becomes a warning, not an unhandled exception."""
    _, botocore_exc = _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = botocore_exc.NoCredentialsError()
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_session.client.return_value = mock_bedrock

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover()

    assert agents == []
    assert any("credentials" in w.lower() for w in warnings)


def test_aws_access_denied_returns_warning():
    """AccessDeniedException returns IAM hint, not a crash."""
    _, botocore_exc = _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.side_effect = botocore_exc.ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "ListAgents",
    )
    mock_bedrock.get_paginator.return_value = mock_paginator
    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover()

    assert any("access denied" in w.lower() or "bedrockagentreadonly" in w.lower() for w in warnings)


def test_aws_ecs_images_collected():
    """ECS tasks produce agent objects with container image refs."""
    _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"
    mock_bedrock = MagicMock()
    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_bedrock.get_paginator.return_value = mock_paginator

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": ["arn:aws:ecs:us-east-1:123:cluster/prod"]}
    mock_ecs.list_tasks.return_value = {"taskArns": ["arn:aws:ecs:us-east-1:123:task/prod/abc"]}
    mock_ecs.describe_tasks.return_value = {
        "tasks": [{"containers": [{"image": "123456.dkr.ecr.us-east-1.amazonaws.com/ml-model:latest"}]}]
    }
    mock_session.client.side_effect = lambda svc, **kw: {"bedrock-agent": mock_bedrock, "ecs": mock_ecs}[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1")

    ecs_agents = [a for a in agents if a.source == "aws-ecs"]
    assert len(ecs_agents) == 1
    assert "ml-model" in ecs_agents[0].name


# ─── Databricks Provider Tests ───────────────────────────────────────────────


def test_databricks_missing_sdk():
    """Helpful error when databricks-sdk is not installed."""
    with patch.dict(sys.modules, {"databricks": None, "databricks.sdk": None, "databricks.sdk.errors": None}):
        with pytest.raises(CloudDiscoveryError, match="databricks-sdk is required"):
            import agent_bom.cloud.databricks as db_mod
            importlib.reload(db_mod)
            db_mod.discover()


def test_databricks_cluster_packages():
    """PyPI libraries on a cluster become Package objects with correct ecosystem."""
    _install_mock_databricks()

    mock_ws = MagicMock()
    cluster = MagicMock()
    cluster.cluster_id = "cluster-123"
    cluster.cluster_name = "ml-cluster"
    cluster.state = "RUNNING"
    mock_ws.clusters.list.return_value = [cluster]

    lib1 = MagicMock()
    lib1.library.pypi = MagicMock(package="langchain==0.1.0")
    lib1.library.maven = None
    lib1.library.jar = None
    lib2 = MagicMock()
    lib2.library.pypi = MagicMock(package="openai==1.12.0")
    lib2.library.maven = None
    lib2.library.jar = None
    status = MagicMock()
    status.library_statuses = [lib1, lib2]
    mock_ws.libraries.cluster_status.return_value = status
    mock_ws.serving_endpoints.list.return_value = []

    with patch("databricks.sdk.WorkspaceClient", return_value=mock_ws):
        importlib.reload(importlib.import_module("agent_bom.cloud.databricks"))
        from agent_bom.cloud.databricks import discover
        agents, warnings = discover(host="https://my.databricks.com", token="fake")

    assert len(agents) == 1
    server = agents[0].mcp_servers[0]
    pkg_names = {p.name for p in server.packages}
    assert "langchain" in pkg_names
    assert "openai" in pkg_names
    assert all(p.ecosystem == "pypi" for p in server.packages)
    assert agents[0].source == "databricks"


def test_databricks_maven_packages():
    """Maven coordinates produce Package objects with ecosystem='maven'."""
    from agent_bom.cloud.databricks import _parse_maven_coords

    pkg = _parse_maven_coords("org.apache.spark:spark-sql_2.12:3.5.0")
    assert pkg is not None
    assert pkg.name == "org.apache.spark:spark-sql_2.12"
    assert pkg.version == "3.5.0"
    assert pkg.ecosystem == "maven"


def test_databricks_pypi_spec_parsing():
    """Various PyPI spec formats are parsed correctly."""
    from agent_bom.cloud.databricks import _parse_pypi_spec

    pkg = _parse_pypi_spec("langchain==0.1.0")
    assert pkg.name == "langchain"
    assert pkg.version == "0.1.0"

    pkg2 = _parse_pypi_spec("openai>=1.0")
    assert pkg2.name == "openai"
    assert pkg2.version == "1.0"

    pkg3 = _parse_pypi_spec("torch")
    assert pkg3.name == "torch"
    assert pkg3.version == "unknown"


# ─── Snowflake Provider Tests ────────────────────────────────────────────────


def test_snowflake_missing_connector():
    """Helpful error when snowflake-connector-python is not installed."""
    with patch.dict(sys.modules, {"snowflake": None, "snowflake.connector": None, "snowflake.connector.errors": None}):
        with pytest.raises(CloudDiscoveryError, match="snowflake-connector-python is required"):
            import agent_bom.cloud.snowflake as sf_mod
            importlib.reload(sf_mod)
            sf_mod.discover()


def test_snowflake_cortex_agents():
    """Cortex Search Services are discovered as agents."""
    mock_sf = _install_mock_snowflake()

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.description = [("name",), ("database_name",), ("schema_name",)]
    mock_cursor.fetchall.side_effect = [
        [("my-search-service", "MY_DB", "PUBLIC")],  # Cortex
        [],  # Snowpark
        [],  # Streamlit
    ]

    with patch.object(mock_sf, "connect", return_value=mock_conn):
        importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
        from agent_bom.cloud.snowflake import discover
        agents, warnings = discover(account="myorg.us-east-1", user="test_user")

    cortex_agents = [a for a in agents if a.source == "snowflake-cortex"]
    assert len(cortex_agents) == 1
    assert cortex_agents[0].name == "cortex:my-search-service"
    assert "snowflake://" in cortex_agents[0].config_path


def test_snowflake_snowpark_packages():
    """Snowpark packages extracted via _discover_snowpark_packages."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_snowpark_packages

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = [
        ("pandas", "2.0.3"),
        ("numpy", "1.24.0"),
        ("scikit-learn", "1.3.0"),
    ]

    packages, warnings = _discover_snowpark_packages(mock_conn, "myorg.us-east-1")

    assert len(packages) == 3
    pkg_names = {p.name for p in packages}
    assert "pandas" in pkg_names
    assert "numpy" in pkg_names
    assert "scikit-learn" in pkg_names
    assert all(p.ecosystem == "pypi" for p in packages)


# ─── Graph Output Tests ──────────────────────────────────────────────────────


def _make_sample_report():
    """Build a small report for graph tests."""
    vuln = Vulnerability(id="CVE-2024-1234", summary="Test vuln", severity=Severity.HIGH)
    pkg = Package(name="express", version="4.18.0", ecosystem="npm", vulnerabilities=[vuln])
    server = MCPServer(
        name="api-server", command="npx", packages=[pkg],
        env={"API_KEY": "***REDACTED***"},
    )
    agent = Agent(
        name="test-agent", agent_type=AgentType.CUSTOM,
        config_path="arn:aws:bedrock:us-east-1:123:agent/ABC",
        source="aws-bedrock", mcp_servers=[server],
    )
    report = AIBOMReport(agents=[agent])
    br = BlastRadius(
        vulnerability=vuln, package=pkg,
        affected_servers=[server], affected_agents=[agent],
        exposed_credentials=["API_KEY"], exposed_tools=[], risk_score=7.5,
    )
    return report, [br]


def test_graph_elements_include_provider_nodes():
    """Cloud-sourced agents get a provider parent node."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii)
    provider_nodes = [e for e in elements if e.get("data", {}).get("type") == "provider"]
    assert len(provider_nodes) == 1
    assert provider_nodes[0]["data"]["id"] == "provider:aws-bedrock"


def test_graph_cve_nodes():
    """Blast radii produce CVE leaf nodes connected to packages."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii, include_cve_nodes=True)
    cve_nodes = [e for e in elements if "cve:" in e.get("data", {}).get("id", "")]
    assert len(cve_nodes) >= 1
    assert cve_nodes[0]["data"]["label"] == "CVE-2024-1234"
    affects_edges = [e for e in elements if e.get("data", {}).get("type") == "affects"]
    assert len(affects_edges) >= 1


def test_graph_no_cve_nodes_when_disabled():
    """CVE nodes can be excluded."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii, include_cve_nodes=False)
    cve_nodes = [e for e in elements if "cve:" in e.get("data", {}).get("id", "")]
    assert len(cve_nodes) == 0


def test_graph_json_format():
    """Graph output produces valid JSON with elements list."""
    from agent_bom.output.graph import build_graph_elements
    report, blast_radii = _make_sample_report()
    elements = build_graph_elements(report, blast_radii)
    result = json.dumps({"elements": elements, "format": "cytoscape"})
    parsed = json.loads(result)
    assert "elements" in parsed
    assert isinstance(parsed["elements"], list)
    assert parsed["format"] == "cytoscape"


# ─── CLI Cloud Flag Tests ────────────────────────────────────────────────────


def test_dry_run_lists_aws_apis():
    """--dry-run --aws mentions AWS APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--aws"])
    assert result.exit_code == 0
    assert "AWS" in result.output or "Bedrock" in result.output


def test_dry_run_lists_databricks_apis():
    """--dry-run --databricks mentions Databricks APIs."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--databricks"])
    assert result.exit_code == 0
    assert "Databricks" in result.output


def test_dry_run_lists_snowflake_apis():
    """--dry-run --snowflake mentions Snowflake APIs."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--snowflake"])
    assert result.exit_code == 0
    assert "Snowflake" in result.output


def test_graph_format_in_help():
    """--format graph is listed as a valid option."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--help"])
    assert "graph" in result.output


# ─── Snowflake Deep Discovery Tests ─────────────────────────────────────────


def test_snowflake_cortex_agents_discovered():
    """SHOW AGENTS returns Cortex Agent objects with correct source."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_cortex_agents

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.description = [("name",), ("database_name",), ("schema_name",), ("owner",), ("profile",)]
    mock_cursor.fetchall.return_value = [
        ("my-agent", "DB1", "PUBLIC", "ADMIN", '{"display_name": "My AI Agent"}'),
    ]

    agents, warnings = _discover_cortex_agents(mock_conn, "myorg")

    assert len(agents) == 1
    assert agents[0].source == "snowflake-cortex-agent"
    assert "My AI Agent" in agents[0].name


def test_snowflake_mcp_servers_discovered():
    """SHOW MCP SERVERS returns MCP server agents with source='snowflake-mcp'."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_mcp_servers

    mock_conn = MagicMock()
    # First cursor for SHOW MCP SERVERS
    show_cursor = MagicMock()
    show_cursor.description = [("name",), ("database_name",), ("schema_name",)]
    show_cursor.fetchall.return_value = [("my-mcp-server", "DB1", "PUBLIC")]

    # Second cursor for DESCRIBE MCP SERVER (returns empty — no YAML spec)
    describe_cursor = MagicMock()
    describe_cursor.description = [("property",), ("property_value",)]
    describe_cursor.fetchall.return_value = []

    mock_conn.cursor.side_effect = [show_cursor, describe_cursor]

    agents, warnings = _discover_mcp_servers(mock_conn, "myorg")

    assert len(agents) == 1
    assert agents[0].source == "snowflake-mcp"
    assert "my-mcp-server" in agents[0].name


def test_snowflake_query_history_parsing():
    """CREATE MCP SERVER/AGENT statements are parsed correctly."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _parse_create_statement_name

    assert _parse_create_statement_name("CREATE MCP SERVER my_server WITH SPEC...") == "my_server"
    assert _parse_create_statement_name("CREATE OR REPLACE MCP SERVER db.schema.srv1 ...") == "srv1"
    assert _parse_create_statement_name("CREATE AGENT IF NOT EXISTS my_agent ...") == "my_agent"
    assert _parse_create_statement_name('CREATE AGENT "MyAgent" ...') == "MyAgent"
    assert _parse_create_statement_name("SELECT 1") is None


def test_snowflake_custom_tools_discovered():
    """User-defined functions are discovered as MCPTool objects."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_custom_tools

    mock_conn = MagicMock()
    mock_cursor_funcs = MagicMock()
    mock_cursor_procs = MagicMock()

    mock_cursor_funcs.fetchall.return_value = [
        ("my_func", "(VARCHAR, NUMBER)", "TABLE", "PYTHON"),
    ]
    mock_cursor_procs.fetchall.return_value = [
        ("my_proc", "(VARCHAR)", "VARCHAR", "SQL"),
    ]

    mock_conn.cursor.side_effect = [mock_cursor_funcs, mock_cursor_procs]

    tools, warnings = _discover_custom_tools(mock_conn, "myorg")

    assert len(tools) == 2
    assert tools[0].name == "my_func"
    assert "PYTHON" in tools[0].description
    assert "external runtime" in tools[0].description
    assert tools[1].name == "my_proc"
    assert "external runtime" not in tools[1].description  # SQL is safe


def test_snowflake_system_execute_sql_flagged():
    """SYSTEM_EXECUTE_SQL tools get a HIGH-RISK flag in their description."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _describe_mcp_server_tools

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor

    yaml_spec = (
        "tools:\n"
        "  - name: run_query\n"
        "    type: SYSTEM_EXECUTE_SQL\n"
        "    description: Execute arbitrary SQL\n"
        "  - name: get_data\n"
        "    type: CUSTOM\n"
        "    description: Fetch data from table\n"
    )
    mock_cursor.description = [("property",), ("property_value",)]
    mock_cursor.fetchall.return_value = [("spec", yaml_spec)]

    tools = _describe_mcp_server_tools(mock_conn, "srv1", "DB1", "PUBLIC", [])

    assert len(tools) == 2
    sql_tool = [t for t in tools if t.name == "run_query"][0]
    assert "HIGH-RISK" in sql_tool.description
    assert "SYSTEM_EXECUTE_SQL" in sql_tool.description
    custom_tool = [t for t in tools if t.name == "get_data"][0]
    assert "HIGH-RISK" not in custom_tool.description


def test_snowflake_query_history_audit():
    """Query history produces audit agents from CREATE statements."""
    _install_mock_snowflake()
    importlib.reload(importlib.import_module("agent_bom.cloud.snowflake"))
    from agent_bom.cloud.snowflake import _discover_from_query_history

    mock_conn = MagicMock()
    mock_cursor = MagicMock()
    mock_conn.cursor.return_value = mock_cursor
    mock_cursor.fetchall.return_value = [
        ("CREATE MCP SERVER my_server SPEC = '...'", "admin", "2025-01-01"),
        ("CREATE AGENT my_agent AS ...", "dev_user", "2025-01-02"),
    ]

    agents, warnings = _discover_from_query_history(mock_conn, "myorg")

    assert len(agents) == 2
    mcp_audit = [a for a in agents if a.source == "snowflake-mcp-audit"]
    agent_audit = [a for a in agents if a.source == "snowflake-agent-audit"]
    assert len(mcp_audit) == 1
    assert len(agent_audit) == 1


# ─── AWS Deep Discovery Tests ───────────────────────────────────────────────


def test_aws_lambda_direct_discovery():
    """Standalone Lambda functions are discovered when include_lambda=True."""
    _install_mock_boto3()

    mock_session = MagicMock()
    mock_session.region_name = "us-east-1"

    mock_bedrock = MagicMock()
    mock_bedrock_paginator = MagicMock()
    mock_bedrock_paginator.paginate.return_value = [{"agentSummaries": []}]
    mock_bedrock.get_paginator.return_value = mock_bedrock_paginator

    mock_ecs = MagicMock()
    mock_ecs.list_clusters.return_value = {"clusterArns": []}

    mock_lambda = MagicMock()
    mock_lambda_paginator = MagicMock()
    mock_lambda_paginator.paginate.return_value = [{
        "Functions": [
            {"FunctionName": "ai-inference", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:ai-inference",
             "Runtime": "python3.12"},
            {"FunctionName": "java-util", "FunctionArn": "arn:aws:lambda:us-east-1:123:function:java-util",
             "Runtime": "java17"},
        ]
    }]
    mock_lambda.get_paginator.return_value = mock_lambda_paginator
    mock_lambda.get_function.return_value = {"Configuration": {"Runtime": "python3.12", "Layers": []}}

    mock_session.client.side_effect = lambda svc, **kw: {
        "bedrock-agent": mock_bedrock, "ecs": mock_ecs, "lambda": mock_lambda,
    }[svc]

    with patch("boto3.Session", return_value=mock_session):
        importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
        from agent_bom.cloud.aws import discover
        agents, warnings = discover(region="us-east-1", include_lambda=True)

    lambda_agents = [a for a in agents if a.source == "aws-lambda"]
    assert len(lambda_agents) == 1
    assert "ai-inference" in lambda_agents[0].name
    assert lambda_agents[0].version == "python3.12"


def test_aws_step_functions_parsing():
    """Step Functions definitions are parsed for Lambda/SageMaker ARNs."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _extract_sfn_task_resources

    definition = {
        "States": {
            "Invoke": {
                "Type": "Task",
                "Resource": "arn:aws:lambda:us-east-1:123:function:my-func",
            },
            "ParallelStep": {
                "Type": "Parallel",
                "Branches": [{"States": {
                    "Branch1": {
                        "Type": "Task",
                        "Resource": "arn:aws:sagemaker:us-east-1:123:endpoint/my-ep",
                    }
                }}],
            },
            "MapStep": {
                "Type": "Map",
                "Iterator": {"States": {
                    "MapTask": {
                        "Type": "Task",
                        "Resource": "arn:aws:lambda:us-east-1:123:function:map-func",
                    }
                }},
            },
        }
    }

    arns = _extract_sfn_task_resources(definition)
    assert len(arns) == 3
    assert "arn:aws:lambda:us-east-1:123:function:my-func" in arns
    assert "arn:aws:sagemaker:us-east-1:123:endpoint/my-ep" in arns
    assert "arn:aws:lambda:us-east-1:123:function:map-func" in arns


def test_aws_ec2_requires_tag_filter():
    """EC2 discovery without tag filter returns a warning, not instances."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _discover_ec2_instances

    mock_session = MagicMock()
    agents, warnings = _discover_ec2_instances(mock_session, "us-east-1", {})

    assert len(agents) == 0
    assert any("tag" in w.lower() for w in warnings)


def test_aws_ec2_tag_discovery():
    """EC2 instances matching tags are discovered as agents."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))
    from agent_bom.cloud.aws import _discover_ec2_instances

    mock_session = MagicMock()
    mock_ec2 = MagicMock()
    mock_session.client.return_value = mock_ec2

    mock_paginator = MagicMock()
    mock_paginator.paginate.return_value = [{
        "Reservations": [{
            "Instances": [{
                "InstanceId": "i-12345",
                "InstanceType": "p4d.24xlarge",
                "ImageId": "ami-abc123",
                "Tags": [{"Key": "Name", "Value": "gpu-training"}],
            }]
        }]
    }]
    mock_ec2.get_paginator.return_value = mock_paginator

    agents, warnings = _discover_ec2_instances(mock_session, "us-east-1", {"Environment": "ai-prod"})

    assert len(agents) == 1
    assert agents[0].source == "aws-ec2"
    assert "gpu-training" in agents[0].name
    assert "p4d.24xlarge" in agents[0].version


def test_aws_eks_reuses_k8s():
    """EKS discovery calls k8s.discover_images() with the cluster as context."""
    _install_mock_boto3()
    importlib.reload(importlib.import_module("agent_bom.cloud.aws"))

    mock_session = MagicMock()
    mock_eks = MagicMock()
    mock_eks.list_clusters.return_value = {"clusters": ["my-eks-cluster"]}
    mock_session.client.return_value = mock_eks

    # Patch at the source (agent_bom.k8s) since _discover_eks_images imports lazily
    with patch("agent_bom.k8s.discover_images") as mock_discover:
        mock_discover.return_value = [("nginx:1.25", "web-pod", "nginx")]
        from agent_bom.cloud.aws import _discover_eks_images
        agents, warnings = _discover_eks_images(mock_session, "us-east-1")

    eks_agents = [a for a in agents if a.source == "aws-eks"]
    assert len(eks_agents) == 1
    assert "my-eks-cluster" in eks_agents[0].name
    mock_discover.assert_called_once_with(all_namespaces=True, context="my-eks-cluster")


# ─── Nebius Provider Tests ──────────────────────────────────────────────────


def _install_mock_nebius():
    """Install a mock nebius SDK in sys.modules."""
    nebius = types.ModuleType("nebius")
    nebius.Client = MagicMock
    sys.modules.setdefault("nebius", nebius)
    return nebius


def test_nebius_missing_sdk():
    """Helpful error when nebius is not installed."""
    with patch.dict(sys.modules, {"nebius": None}):
        import agent_bom.cloud.nebius as nb_mod
        try:
            importlib.reload(nb_mod)
        except Exception:
            pass
        with pytest.raises(CloudDiscoveryError, match="nebius is required"):
            from agent_bom.cloud.nebius import discover
            discover()


def test_nebius_k8s_clusters():
    """Nebius K8s clusters are discovered as agents."""
    _install_mock_nebius()
    importlib.reload(importlib.import_module("agent_bom.cloud.nebius"))
    from agent_bom.cloud.nebius import discover

    mock_client = MagicMock()
    mock_cluster = MagicMock()
    mock_cluster.id = "cluster-abc"
    mock_cluster.name = "gpu-cluster"
    mock_cluster.status = "RUNNING"
    mock_client.kubernetes.clusters.list.return_value = [mock_cluster]
    mock_client.containers = None  # No container service

    with patch("nebius.Client", return_value=mock_client):
        agents, warnings = discover(api_key="fake-key", project_id="proj-123")

    k8s_agents = [a for a in agents if a.source == "nebius-k8s"]
    assert len(k8s_agents) == 1
    assert "gpu-cluster" in k8s_agents[0].name


# ─── CLI Deep Flag Tests ────────────────────────────────────────────────────


def test_dry_run_lists_nebius_apis():
    """--dry-run --nebius mentions Nebius APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--nebius"])
    assert result.exit_code == 0
    assert "Nebius" in result.output


def test_dry_run_aws_lambda_flag():
    """--dry-run --aws --aws-include-lambda mentions Lambda ListFunctions."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--aws", "--aws-include-lambda"])
    assert result.exit_code == 0
    assert "Lambda" in result.output
    assert "ListFunctions" in result.output


# ─── Hugging Face Provider Tests ──────────────────────────────────────────


def _install_mock_huggingface_hub():
    """Install a mock huggingface-hub in sys.modules."""
    hf_hub = types.ModuleType("huggingface_hub")

    mock_api_class = MagicMock()
    hf_hub.HfApi = mock_api_class

    sys.modules.setdefault("huggingface_hub", hf_hub)
    return hf_hub


def test_hf_missing_sdk():
    """Helpful error when huggingface-hub is not installed."""
    with patch.dict(sys.modules, {"huggingface_hub": None}):
        with pytest.raises(CloudDiscoveryError, match="huggingface-hub is required"):
            import agent_bom.cloud.huggingface as hf_mod
            importlib.reload(hf_mod)
            hf_mod.discover()


def test_hf_models_discovered():
    """HF models are discovered with framework packages extracted."""
    _install_mock_huggingface_hub()
    importlib.reload(importlib.import_module("agent_bom.cloud.huggingface"))
    from agent_bom.cloud.huggingface import discover

    mock_api = MagicMock()
    mock_model = MagicMock()
    mock_model.id = "user/my-bert-model"
    mock_model.modelId = "user/my-bert-model"
    mock_model.library_name = "transformers"
    mock_model.pipeline_tag = "text-classification"
    mock_model.tags = ["pytorch"]

    mock_api.list_models.return_value = [mock_model]
    mock_api.list_spaces.return_value = []
    mock_api.list_inference_endpoints.return_value = []

    with patch("huggingface_hub.HfApi", return_value=mock_api):
        agents, warnings = discover(token="fake-token", username="user")

    model_agents = [a for a in agents if a.source == "huggingface-model"]
    assert len(model_agents) == 1
    assert "my-bert-model" in model_agents[0].name
    # Framework packages extracted
    pkgs = model_agents[0].mcp_servers[0].packages
    pkg_names = {p.name for p in pkgs}
    assert "transformers" in pkg_names
    assert "torch" in pkg_names  # from "pytorch" tag


def test_hf_spaces_discovered():
    """HF Spaces are discovered with SDK packages."""
    _install_mock_huggingface_hub()
    importlib.reload(importlib.import_module("agent_bom.cloud.huggingface"))
    from agent_bom.cloud.huggingface import discover

    mock_api = MagicMock()
    mock_api.list_models.return_value = []

    mock_space = MagicMock()
    mock_space.id = "user/my-gradio-app"
    mock_space.sdk = "gradio"
    mock_api.list_spaces.return_value = [mock_space]
    mock_api.list_inference_endpoints.return_value = []

    with patch("huggingface_hub.HfApi", return_value=mock_api):
        agents, warnings = discover(token="fake-token", username="user")

    space_agents = [a for a in agents if a.source == "huggingface-space"]
    assert len(space_agents) == 1
    assert "gradio-app" in space_agents[0].name
    pkgs = space_agents[0].mcp_servers[0].packages
    assert any(p.name == "gradio" for p in pkgs)


def test_hf_extract_framework_packages():
    """Framework package extraction maps library names to PyPI packages."""
    _install_mock_huggingface_hub()
    importlib.reload(importlib.import_module("agent_bom.cloud.huggingface"))
    from agent_bom.cloud.huggingface import _extract_framework_packages

    pkgs = _extract_framework_packages("transformers", ["pytorch", "safetensors"])
    names = {p.name for p in pkgs}
    assert "transformers" in names
    assert "torch" in names
    assert "safetensors" in names
    assert all(p.ecosystem == "pypi" for p in pkgs)

    # No duplicates
    pkgs2 = _extract_framework_packages("pytorch", ["pytorch"])
    assert len(pkgs2) == 1


# ─── W&B Provider Tests ──────────────────────────────────────────────────


def _install_mock_wandb():
    """Install a mock wandb in sys.modules."""
    wandb = types.ModuleType("wandb")
    wandb.Api = MagicMock
    sys.modules.setdefault("wandb", wandb)
    return wandb


def test_wandb_missing_sdk():
    """Helpful error when wandb is not installed."""
    with patch.dict(sys.modules, {"wandb": None}):
        with pytest.raises(CloudDiscoveryError, match="wandb is required"):
            import agent_bom.cloud.wandb_provider as wb_mod
            importlib.reload(wb_mod)
            wb_mod.discover()


def test_wandb_requirement_parsing():
    """W&B requirement strings are parsed into Package objects."""
    _install_mock_wandb()
    importlib.reload(importlib.import_module("agent_bom.cloud.wandb_provider"))
    from agent_bom.cloud.wandb_provider import _parse_requirement

    pkg = _parse_requirement("torch==2.1.0")
    assert pkg.name == "torch"
    assert pkg.version == "2.1.0"
    assert pkg.ecosystem == "pypi"

    pkg2 = _parse_requirement("numpy>=1.24")
    assert pkg2.name == "numpy"
    assert pkg2.version == "1.24"

    pkg3 = _parse_requirement("transformers[torch]==4.36.0")
    assert pkg3.name == "transformers"
    assert pkg3.version == "4.36.0"

    assert _parse_requirement("") is None
    assert _parse_requirement("# comment") is None
    assert _parse_requirement("-e .") is None


def test_wandb_metadata_extraction():
    """Package metadata is extracted from W&B run config."""
    _install_mock_wandb()
    importlib.reload(importlib.import_module("agent_bom.cloud.wandb_provider"))
    from agent_bom.cloud.wandb_provider import _extract_packages_from_metadata

    config = {"_wandb": {"requirements": ["torch==2.1.0", "numpy==1.24.0"]}}
    metadata = {}
    pkgs = _extract_packages_from_metadata(config, metadata)
    names = {p.name for p in pkgs}
    assert "torch" in names
    assert "numpy" in names


# ─── MLflow Provider Tests ────────────────────────────────────────────────


def _install_mock_mlflow():
    """Install a mock mlflow in sys.modules."""
    mlflow = types.ModuleType("mlflow")
    mlflow.MlflowClient = MagicMock
    sys.modules.setdefault("mlflow", mlflow)
    return mlflow


def test_mlflow_missing_sdk():
    """Helpful error when mlflow is not installed."""
    with patch.dict(sys.modules, {"mlflow": None}):
        with pytest.raises(CloudDiscoveryError, match="mlflow is required"):
            import agent_bom.cloud.mlflow_provider as ml_mod
            importlib.reload(ml_mod)
            ml_mod.discover()


def test_mlflow_flavor_packages():
    """MLflow model flavors are mapped to PyPI packages."""
    _install_mock_mlflow()
    importlib.reload(importlib.import_module("agent_bom.cloud.mlflow_provider"))
    from agent_bom.cloud.mlflow_provider import _extract_flavor_packages

    pkgs = _extract_flavor_packages("models:/my-model/Production/sklearn")
    assert len(pkgs) == 1
    assert pkgs[0].name == "scikit-learn"

    pkgs2 = _extract_flavor_packages("runs:/abc123/model/pytorch")
    assert pkgs2[0].name == "torch"

    pkgs3 = _extract_flavor_packages("s3://bucket/model")
    assert len(pkgs3) == 0


def test_mlflow_requirements_parsing():
    """MLflow requirements.txt content is parsed correctly."""
    _install_mock_mlflow()
    importlib.reload(importlib.import_module("agent_bom.cloud.mlflow_provider"))
    from agent_bom.cloud.mlflow_provider import _parse_requirements_txt

    content = "scikit-learn==1.3.0\nnumpy>=1.24\n# comment\ntorch\n"
    pkgs = _parse_requirements_txt(content)
    assert len(pkgs) == 3
    assert pkgs[0].name == "scikit-learn"
    assert pkgs[0].version == "1.3.0"
    assert pkgs[2].name == "torch"
    assert pkgs[2].version == "unknown"


# ─── OpenAI Provider Tests ───────────────────────────────────────────────


def _install_mock_openai():
    """Install a mock openai in sys.modules."""
    openai = types.ModuleType("openai")
    openai.OpenAI = MagicMock
    openai.beta = MagicMock()
    sys.modules.setdefault("openai", openai)
    return openai


def test_openai_missing_sdk():
    """Helpful error when openai is not installed."""
    with patch.dict(sys.modules, {"openai": None}):
        with pytest.raises(CloudDiscoveryError, match="openai is required"):
            import agent_bom.cloud.openai_provider as oa_mod
            importlib.reload(oa_mod)
            oa_mod.discover()


def test_openai_assistants_discovered():
    """OpenAI Assistants are discovered with tools mapped."""
    _install_mock_openai()
    importlib.reload(importlib.import_module("agent_bom.cloud.openai_provider"))
    from agent_bom.cloud.openai_provider import discover

    mock_client = MagicMock()

    # Mock assistant
    mock_asst = MagicMock()
    mock_asst.id = "asst_abc123"
    mock_asst.name = "My Research Assistant"
    mock_asst.model = "gpt-4o"
    mock_asst.instructions = "You are a helpful research assistant."

    mock_tool_ci = MagicMock()
    mock_tool_ci.type = "code_interpreter"
    mock_tool_fs = MagicMock()
    mock_tool_fs.type = "file_search"
    mock_asst.tools = [mock_tool_ci, mock_tool_fs]

    mock_response = MagicMock()
    mock_response.data = [mock_asst]
    mock_client.beta.assistants.list.return_value = mock_response

    # Mock fine-tuning (empty)
    mock_ft_response = MagicMock()
    mock_ft_response.data = []
    mock_client.fine_tuning.jobs.list.return_value = mock_ft_response

    with patch("openai.OpenAI", return_value=mock_client):
        agents, warnings = discover(api_key="sk-fake-key")

    asst_agents = [a for a in agents if a.source == "openai-assistant"]
    assert len(asst_agents) == 1
    assert "Research Assistant" in asst_agents[0].name
    assert asst_agents[0].version == "gpt-4o"

    # Tools mapped
    tools = asst_agents[0].mcp_servers[0].tools
    tool_names = [t.name for t in tools]
    assert "code_interpreter" in tool_names
    assert "file_search" in tool_names
    assert "HIGH-RISK" in tools[0].description  # code_interpreter is flagged


def test_openai_fine_tunes_discovered():
    """OpenAI fine-tuned models are discovered."""
    _install_mock_openai()
    importlib.reload(importlib.import_module("agent_bom.cloud.openai_provider"))
    from agent_bom.cloud.openai_provider import discover

    mock_client = MagicMock()

    # Empty assistants
    mock_asst_response = MagicMock()
    mock_asst_response.data = []
    mock_client.beta.assistants.list.return_value = mock_asst_response

    # Mock fine-tune
    mock_ft = MagicMock()
    mock_ft.id = "ftjob-abc123"
    mock_ft.model = "gpt-4o-mini-2024-07-18"
    mock_ft.fine_tuned_model = "ft:gpt-4o-mini:org::abc123"
    mock_ft.status = "succeeded"
    mock_ft.training_file = "file-xyz789"

    mock_ft_response = MagicMock()
    mock_ft_response.data = [mock_ft]
    mock_client.fine_tuning.jobs.list.return_value = mock_ft_response

    with patch("openai.OpenAI", return_value=mock_client):
        agents, warnings = discover(api_key="sk-fake-key")

    ft_agents = [a for a in agents if a.source == "openai-fine-tune"]
    assert len(ft_agents) == 1
    assert "ft:gpt-4o-mini" in ft_agents[0].name
    assert "succeeded" in ft_agents[0].version


# ─── Azure Provider Tests ─────────────────────────────────────────────────


def _install_mock_azure():
    """Install mock Azure SDK modules in sys.modules."""
    # azure.identity
    azure = types.ModuleType("azure")
    azure_identity = types.ModuleType("azure.identity")
    azure_identity.DefaultAzureCredential = MagicMock
    azure.identity = azure_identity

    # azure.mgmt.appcontainers
    azure_mgmt = types.ModuleType("azure.mgmt")
    azure_mgmt_appcontainers = types.ModuleType("azure.mgmt.appcontainers")
    azure_mgmt_appcontainers.ContainerAppsAPIClient = MagicMock
    azure_mgmt.appcontainers = azure_mgmt_appcontainers

    # azure.mgmt.resource
    azure_mgmt_resource = types.ModuleType("azure.mgmt.resource")
    azure_mgmt_resource.ResourceManagementClient = MagicMock
    azure_mgmt.resource = azure_mgmt_resource

    # azure.ai.projects
    azure_ai = types.ModuleType("azure.ai")
    azure_ai_projects = types.ModuleType("azure.ai.projects")
    azure_ai_projects.AIProjectClient = MagicMock
    azure_ai.projects = azure_ai_projects

    sys.modules.setdefault("azure", azure)
    sys.modules.setdefault("azure.identity", azure_identity)
    sys.modules.setdefault("azure.mgmt", azure_mgmt)
    sys.modules.setdefault("azure.mgmt.appcontainers", azure_mgmt_appcontainers)
    sys.modules.setdefault("azure.mgmt.resource", azure_mgmt_resource)
    sys.modules.setdefault("azure.ai", azure_ai)
    sys.modules.setdefault("azure.ai.projects", azure_ai_projects)
    return azure


def test_azure_missing_sdk():
    """Helpful error when azure-identity is not installed."""
    with patch.dict(sys.modules, {"azure.identity": None, "azure": None}):
        with pytest.raises(CloudDiscoveryError, match="azure-identity is required"):
            import agent_bom.cloud.azure as az_mod
            importlib.reload(az_mod)
            az_mod.discover(subscription_id="sub-123")


def test_azure_missing_subscription():
    """Warning when AZURE_SUBSCRIPTION_ID is not set."""
    _install_mock_azure()
    importlib.reload(importlib.import_module("agent_bom.cloud.azure"))
    from agent_bom.cloud.azure import discover

    with patch.dict("os.environ", {}, clear=True):
        agents, warnings = discover()
    assert len(agents) == 0
    assert any("AZURE_SUBSCRIPTION_ID" in w for w in warnings)


def test_azure_container_apps_discovered():
    """Azure Container Apps are discovered with images extracted."""
    _install_mock_azure()
    importlib.reload(importlib.import_module("agent_bom.cloud.azure"))
    from agent_bom.cloud.azure import discover

    mock_credential = MagicMock()
    mock_client = MagicMock()

    # Mock a Container App with a container image
    mock_container = MagicMock()
    mock_container.name = "api-container"
    mock_container.image = "myregistry.azurecr.io/ai-agent:v1.2"

    mock_template = MagicMock()
    mock_template.containers = [mock_container]

    mock_app = MagicMock()
    mock_app.name = "my-ai-agent-app"
    mock_app.id = "/subscriptions/sub-123/resourceGroups/rg-ai/providers/Microsoft.App/containerApps/my-ai-agent-app"
    mock_app.template = mock_template

    mock_client.container_apps.list_by_subscription.return_value = [mock_app]

    with patch("azure.identity.DefaultAzureCredential", return_value=mock_credential), \
         patch("azure.mgmt.appcontainers.ContainerAppsAPIClient", return_value=mock_client):
        agents, warnings = discover(subscription_id="sub-123")

    ca_agents = [a for a in agents if a.source == "azure-container-apps"]
    assert len(ca_agents) == 1
    assert "my-ai-agent-app" in ca_agents[0].name
    assert ca_agents[0].mcp_servers[0].args[1] == "myregistry.azurecr.io/ai-agent:v1.2"


def test_azure_ai_foundry_discovered():
    """Azure AI Foundry ML workspaces are discovered."""
    _install_mock_azure()
    importlib.reload(importlib.import_module("agent_bom.cloud.azure"))
    from agent_bom.cloud.azure import discover

    mock_credential = MagicMock()
    mock_ca_client = MagicMock()
    mock_ca_client.container_apps.list_by_subscription.return_value = []

    mock_rm_client = MagicMock()
    mock_workspace = MagicMock()
    mock_workspace.name = "my-ml-workspace"
    mock_workspace.id = "/subscriptions/sub-123/resourceGroups/rg-ai/providers/Microsoft.MachineLearningServices/workspaces/my-ml-workspace"
    mock_rm_client.resources.list.return_value = [mock_workspace]

    with patch("azure.identity.DefaultAzureCredential", return_value=mock_credential), \
         patch("azure.mgmt.appcontainers.ContainerAppsAPIClient", return_value=mock_ca_client), \
         patch("azure.mgmt.resource.ResourceManagementClient", return_value=mock_rm_client):
        agents, warnings = discover(subscription_id="sub-123")

    ai_agents = [a for a in agents if a.source == "azure-ai-foundry"]
    assert len(ai_agents) == 1
    assert "my-ml-workspace" in ai_agents[0].name


def test_azure_container_apps_by_resource_group():
    """Azure Container Apps filtered by resource group."""
    _install_mock_azure()
    importlib.reload(importlib.import_module("agent_bom.cloud.azure"))
    from agent_bom.cloud.azure import discover

    mock_credential = MagicMock()
    mock_client = MagicMock()

    mock_container = MagicMock()
    mock_container.name = "sidecar"
    mock_container.image = "mcr.microsoft.com/agent:latest"
    mock_template = MagicMock()
    mock_template.containers = [mock_container]
    mock_app = MagicMock()
    mock_app.name = "rg-scoped-app"
    mock_app.id = "azure://rg-scoped-app"
    mock_app.template = mock_template

    mock_client.container_apps.list_by_resource_group.return_value = [mock_app]

    with patch("azure.identity.DefaultAzureCredential", return_value=mock_credential), \
         patch("azure.mgmt.appcontainers.ContainerAppsAPIClient", return_value=mock_client):
        agents, warnings = discover(subscription_id="sub-123", resource_group="rg-ai")

    assert len(agents) >= 1
    # Should use list_by_resource_group, not list_by_subscription
    mock_client.container_apps.list_by_resource_group.assert_called_once_with("rg-ai")


# ─── GCP Provider Tests ──────────────────────────────────────────────────


def _install_mock_gcp():
    """Install mock GCP SDK modules in sys.modules."""
    google = types.ModuleType("google")
    google_cloud = types.ModuleType("google.cloud")
    google_cloud_aiplatform = types.ModuleType("google.cloud.aiplatform")
    google_cloud_aiplatform.init = MagicMock()
    google_cloud_aiplatform.Endpoint = MagicMock()
    google_cloud.aiplatform = google_cloud_aiplatform

    google_cloud_run_v2 = types.ModuleType("google.cloud.run_v2")
    google_cloud_run_v2.ServicesClient = MagicMock
    google_cloud.run_v2 = google_cloud_run_v2

    google_auth = types.ModuleType("google.auth")
    google.auth = google_auth
    google.cloud = google_cloud

    sys.modules.setdefault("google", google)
    sys.modules.setdefault("google.auth", google_auth)
    sys.modules.setdefault("google.cloud", google_cloud)
    sys.modules.setdefault("google.cloud.aiplatform", google_cloud_aiplatform)
    sys.modules.setdefault("google.cloud.run_v2", google_cloud_run_v2)
    return google


def test_gcp_missing_sdk():
    """Helpful error when google-cloud-aiplatform is not installed."""
    with patch.dict(sys.modules, {"google.cloud.aiplatform": None, "google.cloud": None, "google": None}):
        with pytest.raises(CloudDiscoveryError, match="google-cloud-aiplatform is required"):
            import agent_bom.cloud.gcp as gcp_mod
            importlib.reload(gcp_mod)
            gcp_mod.discover(project_id="my-project")


def test_gcp_missing_project():
    """Warning when GOOGLE_CLOUD_PROJECT is not set."""
    _install_mock_gcp()
    importlib.reload(importlib.import_module("agent_bom.cloud.gcp"))
    from agent_bom.cloud.gcp import discover

    with patch.dict("os.environ", {}, clear=True):
        agents, warnings = discover()
    assert len(agents) == 0
    assert any("GOOGLE_CLOUD_PROJECT" in w for w in warnings)


def test_gcp_vertex_ai_endpoints_discovered():
    """Vertex AI endpoints with deployed models are discovered."""
    _install_mock_gcp()
    importlib.reload(importlib.import_module("agent_bom.cloud.gcp"))
    from agent_bom.cloud.gcp import discover

    mock_deployed_model = MagicMock()
    mock_deployed_model.model = "projects/123/locations/us-central1/models/my-model"
    mock_deployed_model.display_name = "bert-classifier"

    mock_gca = MagicMock()
    mock_gca.deployed_models = [mock_deployed_model]

    mock_endpoint = MagicMock()
    mock_endpoint.display_name = "prod-endpoint"
    mock_endpoint.resource_name = "projects/123/locations/us-central1/endpoints/456"
    mock_endpoint.gca_resource = mock_gca

    with patch("google.cloud.aiplatform.init"), \
         patch("google.cloud.aiplatform.Endpoint.list", return_value=[mock_endpoint]):
        agents, warnings = discover(project_id="my-project", region="us-central1")

    vertex_agents = [a for a in agents if a.source == "gcp-vertex-ai"]
    assert len(vertex_agents) == 1
    assert "prod-endpoint" in vertex_agents[0].name
    assert len(vertex_agents[0].mcp_servers) == 1
    assert "bert-classifier" in vertex_agents[0].mcp_servers[0].name


def test_gcp_cloud_run_services_discovered():
    """Cloud Run services with container images are discovered."""
    _install_mock_gcp()
    importlib.reload(importlib.import_module("agent_bom.cloud.gcp"))
    from agent_bom.cloud.gcp import discover

    mock_container = MagicMock()
    mock_container.image = "gcr.io/my-project/ai-service:v2"

    mock_template = MagicMock()
    mock_template.containers = [mock_container]

    mock_service = MagicMock()
    mock_service.name = "projects/my-project/locations/us-central1/services/ai-service"
    mock_service.template = mock_template

    mock_client = MagicMock()
    mock_client.list_services.return_value = [mock_service]

    with patch("google.cloud.aiplatform.init"), \
         patch("google.cloud.aiplatform.Endpoint.list", return_value=[]), \
         patch("google.cloud.run_v2.ServicesClient", return_value=mock_client):
        agents, warnings = discover(project_id="my-project", region="us-central1")

    run_agents = [a for a in agents if a.source == "gcp-cloud-run"]
    assert len(run_agents) == 1
    assert "ai-service" in run_agents[0].name
    assert "gcr.io/my-project/ai-service:v2" in run_agents[0].mcp_servers[0].args


def test_gcp_vertex_and_cloud_run_combined():
    """Both Vertex AI and Cloud Run are discovered in a single scan."""
    _install_mock_gcp()
    importlib.reload(importlib.import_module("agent_bom.cloud.gcp"))
    from agent_bom.cloud.gcp import discover

    # Vertex AI
    mock_deployed = MagicMock()
    mock_deployed.model = "projects/123/locations/us-central1/models/llm"
    mock_deployed.display_name = "llm-model"
    mock_gca = MagicMock()
    mock_gca.deployed_models = [mock_deployed]
    mock_ep = MagicMock()
    mock_ep.display_name = "llm-endpoint"
    mock_ep.resource_name = "projects/123/locations/us-central1/endpoints/789"
    mock_ep.gca_resource = mock_gca

    # Cloud Run
    mock_container = MagicMock()
    mock_container.image = "gcr.io/proj/svc:v1"
    mock_template = MagicMock()
    mock_template.containers = [mock_container]
    mock_svc = MagicMock()
    mock_svc.name = "projects/proj/locations/us-central1/services/svc"
    mock_svc.template = mock_template
    mock_run_client = MagicMock()
    mock_run_client.list_services.return_value = [mock_svc]

    with patch("google.cloud.aiplatform.init"), \
         patch("google.cloud.aiplatform.Endpoint.list", return_value=[mock_ep]), \
         patch("google.cloud.run_v2.ServicesClient", return_value=mock_run_client):
        agents, warnings = discover(project_id="proj", region="us-central1")

    assert len([a for a in agents if a.source == "gcp-vertex-ai"]) == 1
    assert len([a for a in agents if a.source == "gcp-cloud-run"]) == 1


# ─── CLI Dry-Run Tests for New Providers ──────────────────────────────────


def test_dry_run_lists_azure_apis():
    """--dry-run --azure mentions Azure APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--azure"])
    assert result.exit_code == 0
    assert "Azure" in result.output


def test_dry_run_lists_gcp_apis():
    """--dry-run --gcp mentions GCP APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--gcp"])
    assert result.exit_code == 0
    assert "GCP" in result.output


def test_dry_run_lists_huggingface_apis():
    """--dry-run --huggingface mentions HF APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--huggingface"])
    assert result.exit_code == 0
    assert "Hugging Face" in result.output


def test_dry_run_lists_wandb_apis():
    """--dry-run --wandb mentions W&B APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--wandb"])
    assert result.exit_code == 0
    assert "W&B" in result.output


def test_dry_run_lists_mlflow_apis():
    """--dry-run --mlflow mentions MLflow in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--mlflow"])
    assert result.exit_code == 0
    assert "MLflow" in result.output


def test_dry_run_lists_openai_apis():
    """--dry-run --openai mentions OpenAI APIs in output."""
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--dry-run", "--openai"])
    assert result.exit_code == 0
    assert "OpenAI" in result.output


# ─── MCP Registry — ClickHouse ────────────────────────────────────────────


def test_clickhouse_in_mcp_registry():
    """ClickHouse MCP server should be in the registry with real data."""
    from pathlib import Path
    registry_path = Path(__file__).parent.parent / "src" / "agent_bom" / "mcp_registry.json"
    data = json.loads(registry_path.read_text())
    assert "mcp-clickhouse" in data["servers"]
    entry = data["servers"]["mcp-clickhouse"]
    assert entry["ecosystem"] == "pypi"
    assert entry["license"] == "Apache-2.0"
    assert entry["risk_level"] == "high"
    assert "CLICKHOUSE_PASSWORD" in entry["credential_env_vars"]
    assert "run_select_query" in entry["tools"]
    assert "list_databases" in entry["tools"]
    assert entry["source_url"] == "https://github.com/ClickHouse/mcp-clickhouse"
