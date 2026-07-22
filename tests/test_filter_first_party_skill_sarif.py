from scripts.filter_first_party_skill_sarif import filter_sarif


def _result(rule_id: str, uri: str, score: float) -> dict:
    return {
        "ruleId": rule_id,
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
        "properties": {"security-severity": score},
    }


def test_filters_only_informational_skill_rows_from_first_party_instruction_files() -> None:
    data = {
        "runs": [
            {
                "tool": {"driver": {"rules": []}},
                "results": [
                    _result("finding/SKILL_RISK", ".cursor/rules/no-competitor-names.mdc", 4.0),
                    _result("finding/SKILL_RISK", "./CLAUDE.md", 6.0),
                    _result("finding/SKILL_RISK", "skills/vendor/SKILL.md", 4.0),
                    _result("finding/SKILL_RISK", "AGENTS.md", 7.0),
                    _result("finding/CVE", "CLAUDE.md", 4.0),
                ],
            }
        ]
    }

    assert filter_sarif(data) == 2
    remaining = data["runs"][0]["results"]
    assert [row["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for row in remaining] == [
        "skills/vendor/SKILL.md",
        "AGENTS.md",
        "CLAUDE.md",
    ]
