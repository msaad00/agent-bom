"""Regression tests for two audit blockers left open after #3626:

1. SARIF ``is_malicious`` was only emitted on the unified-finding path, not on
   ``_cve_sarif_result`` — the path a ``MAL-`` package actually takes.
2. The reachability source-masker did not strip PHP heredoc/nowdoc bodies, so an
   identifier like ``$client->request`` inside a SQL/HTML template produced a
   false call site (and a false ``function_reachable`` stamp).
"""

from __future__ import annotations

from agent_bom.ast_source_mask import mask_line_comments_and_strings


def test_php_heredoc_body_is_masked():
    src = (
        "function handle() {\n"
        "    $sql = <<<EOT\n"
        "        $client->request('GET', $url);\n"
        "    EOT;\n"
        "    return $sql;\n"
        "}\n"
    )
    masked = mask_line_comments_and_strings(src, hash_comments=True, heredoc=True)
    assert "request" not in masked
    assert "$client" not in masked
    # Real code around the heredoc survives.
    assert "function handle" in masked
    assert "return" in masked
    # Line count preserved so downstream line numbers stay accurate.
    assert masked.count("\n") == src.count("\n")


def test_php_nowdoc_body_is_masked():
    src = "$q = <<<'SQL'\nClient::request();\nSQL;\n"
    masked = mask_line_comments_and_strings(src, hash_comments=True, heredoc=True)
    assert "request" not in masked
    assert "Client" not in masked


def test_heredoc_disabled_by_default_leaves_body():
    src = "$q = <<<EOT\nClient::request();\nEOT;\n"
    masked = mask_line_comments_and_strings(src, hash_comments=True)
    # Without heredoc=True (e.g. Swift), behaviour is unchanged.
    assert "request" in masked


def test_php_reachability_no_false_edge_from_heredoc():
    from agent_bom.ast_php import _php_call_sites

    body = (
        "$html = <<<HTML\n"
        "  see $client->request() docs\n"
        "HTML;\n"
    )
    sites = _php_call_sites(body, line_offset=1)
    assert all("request" not in s.name for s in sites), [s.name for s in sites]


def test_sarif_cve_path_carries_is_malicious():
    import json

    from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
    from agent_bom.output.sarif import to_sarif

    vuln = Vulnerability(
        id="MAL-2025-20690",
        summary="known malicious package (event-stream backdoor)",
        severity=Severity.CRITICAL,
        cvss_score=9.8,
    )
    pkg = Package(
        name="flatmap-stream",
        version="0.1.1",
        ecosystem="npm",
        vulnerabilities=[vuln],
        is_direct=True,
    )
    pkg.is_malicious = True
    pkg.malicious_reason = "known malicious package (event-stream backdoor)"
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )
    br.calculate_risk_score()
    report = AIBOMReport()

    doc = to_sarif(report, blast_radii=[br])
    results = doc["runs"][0]["results"]
    mal = [r for r in results if r["ruleId"] == "MAL-2025-20690"]
    assert mal, "malicious package produced no SARIF result on the CVE path"
    props = mal[0]["properties"]
    assert props.get("is_malicious") is True, props
    assert props.get("malicious_reason"), props
    # And it survives serialization (what GitHub Security ingests).
    assert "is_malicious" in json.dumps(doc)
