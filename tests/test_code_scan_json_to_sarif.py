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
    assert len(sarif["runs"][0]["results"]) == 2
    assert "sk-test-value" not in encoded
    assert "secret-value" not in encoded
    assert "token=abc123" not in encoded
