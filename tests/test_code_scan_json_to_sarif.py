import json

from scripts.code_scan_json_to_sarif import convert


def test_code_scan_json_to_sarif_redacts_api_key_component_name():
    sarif = convert(
        {
            "flow_findings": [
                {
                    "category": "sql_string_construction",
                    "title": "SQL query is built dynamically",
                    "detail": "query uses token=abc123 before execute",
                    "file": "api/db.py",
                    "line": 42,
                }
            ],
            "ai_components": {
                "api_keys": [
                    {
                        "component_type": "api_key",
                        "name": "sk-test-value",
                        "severity": "critical",
                        "file_path": "settings.py",
                        "line_number": 7,
                        "description": "hardcoded api_key=secret-value",
                    }
                ]
            },
        }
    )

    encoded = json.dumps(sarif)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert "sk-test-value" not in encoded
    assert "secret-value" not in encoded
    assert "token=abc123" not in encoded


def test_code_scan_json_to_sarif_filters_inventory_noise_from_security_tab():
    sarif = convert(
        {
            "flow_findings": [
                {
                    "category": "sql_string_construction",
                    "title": "SQL query is built dynamically",
                    "severity": "medium",
                    "detail": "review this manually",
                    "file": "api/db.py",
                    "line": 42,
                },
                {
                    "category": "ssrf_url_construction",
                    "title": "Untrusted URL reaches HTTP client",
                    "severity": "high",
                    "detail": "user URL reaches httpx.get",
                    "file": "api/client.py",
                    "line": 12,
                },
            ],
            "ai_components": {
                "components": [
                    {
                        "stable_id": "deprecated-1",
                        "component_type": "deprecated_model",
                        "name": "gpt-3.5-turbo-0301",
                        "severity": "medium",
                        "file_path": "ai_components/patterns.py",
                        "line_number": 676,
                        "description": "Deprecated model inventory finding",
                    },
                    {
                        "stable_id": "api-key-1",
                        "component_type": "api_key",
                        "name": "sk-test-value",
                        "severity": "critical",
                        "file_path": "settings.py",
                        "line_number": 7,
                        "description": "hardcoded api_key=secret-value",
                    },
                ],
                "deprecated_models": [
                    {
                        "stable_id": "deprecated-1",
                        "component_type": "deprecated_model",
                        "name": "gpt-3.5-turbo-0301",
                        "severity": "medium",
                        "file_path": "ai_components/patterns.py",
                        "line_number": 676,
                        "description": "Deprecated model inventory finding",
                    }
                ],
            },
        }
    )

    encoded = json.dumps(sarif)
    results = sarif["runs"][0]["results"]
    rule_ids = {result["ruleId"] for result in results}
    assert len(results) == 2
    assert "agent-bom-code-flow/ssrf_url_construction" in rule_ids
    assert "agent-bom-ai-component/api_key" in rule_ids
    assert "deprecated_model" not in encoded
    assert "gpt-3.5-turbo-0301" not in encoded
    assert "secret-value" not in encoded
