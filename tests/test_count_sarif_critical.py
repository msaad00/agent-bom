"""Regression: release self-scan must not treat medium/low skill SARIF as critical."""

from __future__ import annotations

from scripts.count_sarif_critical import count_critical_results


def test_count_sarif_critical_ignores_skill_warning_and_note() -> None:
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "finding/SKILL_RISK",
                                "properties": {"security-severity": "4.0"},
                            }
                        ]
                    }
                },
                "results": [
                    {"ruleId": "finding/SKILL_RISK", "level": "warning", "properties": {}},
                    {"ruleId": "finding/SKILL_RISK", "level": "note", "properties": {}},
                ],
            }
        ]
    }
    assert count_critical_results(sarif) == 0


def test_count_sarif_critical_counts_security_severity_ge_9() -> None:
    sarif = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    {
                        "ruleId": "CVE-2024-0001",
                        "level": "error",
                        "properties": {"security-severity": "9.1"},
                    },
                    {
                        "ruleId": "CVE-2024-0002",
                        "level": "error",
                        "properties": {"security-severity": "7.5"},
                    },
                ],
            }
        ]
    }
    assert count_critical_results(sarif) == 1


def test_count_sarif_critical_uses_rule_security_severity_fallback() -> None:
    sarif = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "rules": [
                            {
                                "id": "CVE-2024-0003",
                                "properties": {"security-severity": "9.0"},
                            }
                        ]
                    }
                },
                "results": [{"ruleId": "CVE-2024-0003", "level": "error", "properties": {}}],
            }
        ]
    }
    assert count_critical_results(sarif) == 1
