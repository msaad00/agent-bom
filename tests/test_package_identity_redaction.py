"""Package coordinates survive redaction without hiding nearby PII or secrets."""

import pytest

from agent_bom.security import mask_email, sanitize_sensitive_payload, sanitize_text, text_requires_redaction


@pytest.mark.parametrize(
    "coordinate",
    [
        "pkg:maven/io.netty/netty-codec@4.1.68.Final",
        "pkg:maven:io.netty:netty-codec@4.1.68.Final",
        "pkg:maven/org.springframework/spring-core@5.3.18.RELEASE",
        "io.netty:netty-codec@4.1.68.Final",
    ],
)
def test_package_coordinates_survive_email_redaction(coordinate):
    assert mask_email(coordinate) == coordinate
    assert sanitize_text(coordinate) == coordinate
    assert not text_requires_redaction(coordinate)
    assert sanitize_sensitive_payload({"purl": coordinate, "node_ids": [coordinate]}) == {"purl": coordinate, "node_ids": [coordinate]}
    text = f"Affected {coordinate}; contact alice@example.com"
    assert sanitize_text(text) == f"Affected {coordinate}; contact a***@e***.com"


@pytest.mark.parametrize(
    "value",
    [
        "pkg:maven/io.netty/alice@example.com",
        "pkg:maven/io.netty/netty@4.1.68.Final?owner=alice@example.com",
        "pkg:maven/io.netty/netty@4.1.68.Final#alice@example.com",
        "pkg:maven/io.netty/netty@4.1.68.Final -> alice@example.com",
    ],
)
def test_package_syntax_does_not_hide_real_email(value):
    assert "alice@example.com" not in sanitize_text(value)


def test_secret_checks_still_apply_inside_package_coordinates():
    token = "ghp_" + "X" * 36
    value = f"pkg:maven/io.netty/{token}@4.1.68.Final"
    assert token not in sanitize_text(value)
    assert token not in str(sanitize_sensitive_payload({"purl": value}))


def test_explicit_email_field_always_masks_email_shaped_values():
    assert sanitize_sensitive_payload({"email": "alice@4.1.68.Final"}) == {"email": "a***@4***.Final"}


@pytest.mark.parametrize(
    "format_name", ["to_redacted_json", "to_cyclonedx", "to_spdx", "to_spdx2", "to_sarif", "to_csv", "to_markdown", "to_html"]
)
def test_report_exports_keep_package_identity_and_redact_adjacent_email(format_name):
    import json

    from agent_bom import output
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer, Package, Severity, Vulnerability

    purl = "pkg:maven/io.netty/netty-codec@4.1.68.Final"
    vulnerability = Vulnerability(id="CVE-2021-37136", severity=Severity.HIGH, summary=f"Affected {purl}; alice@example.com")
    package = Package(name="io.netty:netty-codec", version="4.1.68.Final", ecosystem="maven", purl=purl, vulnerabilities=[vulnerability])
    server = MCPServer(name="server", command="java", packages=[package])
    agent = Agent(name="agent", agent_type=AgentType.CUSTOM, config_path="config.json", mcp_servers=[server])
    blast = BlastRadius(
        package=package,
        vulnerability=vulnerability,
        affected_servers=[server],
        affected_agents=[agent],
        exposed_credentials=[],
        exposed_tools=[],
    )
    report = AIBOMReport(agents=[agent], blast_radii=[blast])
    rendered = getattr(output, format_name)(report)
    text = json.dumps(rendered) if isinstance(rendered, dict) else rendered
    assert purl in text
    assert "alice@example.com" not in text
    assert "n***@4***.Final" not in text
