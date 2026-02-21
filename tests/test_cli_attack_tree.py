"""Tests for CLI attack flow tree rendering."""
from io import StringIO
from unittest.mock import patch

from rich.console import Console

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output import print_attack_flow_tree


def _make_report(n_findings=3, with_tools=False, with_creds=False):
    """Create a test report with N blast radius findings."""
    agents = [Agent(name="test-agent", agent_type=AgentType.CUSTOM, config_path="/test")]
    servers = [MCPServer(name="test-server", command="npx", args=["@test/mcp"])]
    agents[0].mcp_servers = servers

    blast_radii = []
    for i in range(n_findings):
        sev = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM][i % 3]
        vuln = Vulnerability(id=f"CVE-2024-{1000+i}", summary=f"Test vuln {i}", severity=sev, cvss_score=9.0 - i)
        pkg = Package(name=f"pkg-{i}", version="1.0.0", ecosystem="npm")
        servers[0].packages.append(pkg)
        tools = [MCPTool(name=f"tool_{j}", description="") for j in range(3)] if with_tools else []
        creds = [f"API_KEY_{j}" for j in range(2)] if with_creds else []
        br = BlastRadius(
            vulnerability=vuln,
            package=pkg,
            affected_servers=servers,
            affected_agents=agents,
            exposed_credentials=creds,
            exposed_tools=tools,
        )
        br.risk_score = 8.0 - i * 0.5
        blast_radii.append(br)

    report = AIBOMReport(agents=agents)
    report.blast_radii = blast_radii
    return report


def test_attack_flow_tree_renders():
    """Call print_attack_flow_tree with a basic report -- should not raise and should contain header."""
    report = _make_report()
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert "Attack Flow Chains" in output


def test_attack_flow_tree_empty():
    """Report with no blast_radii should produce no output."""
    report = AIBOMReport(agents=[])
    report.blast_radii = []
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert output == ""


def test_attack_flow_tree_severity_coloring():
    """Report with CRITICAL finding should show CRITICAL in output."""
    report = _make_report(n_findings=1)
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert "critical" in output.lower()


def test_attack_flow_tree_limit():
    """Report with 20 findings should cap at 15 and show overflow message."""
    report = _make_report(n_findings=20)
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True, highlight=False)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert "and 5 more" in output


def test_attack_flow_tree_credentials_tools():
    """Report with credentials and tools should display key and wrench icons."""
    report = _make_report(n_findings=1, with_creds=True, with_tools=True)
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert "\U0001f511" in output  # 🔑
    assert "\U0001f527" in output  # 🔧


def test_agent_tree_labels():
    """Agent tree should show explicit Agent: and MCP Server: labels."""
    from io import StringIO
    from unittest.mock import patch

    from rich.console import Console

    from agent_bom.output import print_agent_tree

    report = _make_report()
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_agent_tree(report)
    output = buf.getvalue()
    assert "Agent:" in output
    assert "MCP Server:" in output


def test_agent_tree_summary_stats():
    """Agent tree should show summary stats (servers, packages)."""
    from io import StringIO
    from unittest.mock import patch

    from rich.console import Console

    from agent_bom.output import print_agent_tree

    report = _make_report()
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_agent_tree(report)
    output = buf.getvalue()
    assert "server" in output.lower()
    assert "package" in output.lower()


def test_attack_flow_tree_label_consistency():
    """Attack flow tree should show MCP Server and Agent labels."""
    from io import StringIO
    from unittest.mock import patch

    from rich.console import Console

    from agent_bom.output import print_attack_flow_tree

    report = _make_report()
    buf = StringIO()
    test_console = Console(file=buf, force_terminal=True)
    with patch("agent_bom.output.console", test_console):
        print_attack_flow_tree(report)
    output = buf.getvalue()
    assert "(MCP Server)" in output
    assert "(Agent)" in output
