from __future__ import annotations

import json

from scripts.emit_github_annotations import emit_annotations


def test_emit_skills_json_annotations(tmp_path):
    result = tmp_path / "skills.json"
    result.write_text(
        json.dumps(
            {
                "report_type": "skills_scan",
                "files": [
                    {
                        "path": "skills/example/SKILL.md",
                        "audit": {
                            "findings": [
                                {
                                    "severity": "high",
                                    "category": "shell_execution",
                                    "title": "Runs shell commands",
                                    "detail": "Skill can execute arbitrary commands",
                                    "source_file": "skills/example/SKILL.md",
                                    "source_line": 12,
                                    "source_column": 5,
                                }
                            ]
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    annotations = emit_annotations(result, max_annotations=50)

    assert annotations == [
        "::warning file=skills/example/SKILL.md,line=12,col=5,title=agent-bom HIGH shell_execution::"
        "Runs shell commands: Skill can execute arbitrary commands"
    ]


def test_emit_sarif_annotations_escapes_workflow_command_fields(tmp_path):
    result = tmp_path / "skills.sarif"
    result.write_text(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "rules": [
                                    {
                                        "id": "SKILL:network,egress",
                                        "name": "Network egress",
                                    }
                                ]
                            }
                        },
                        "results": [
                            {
                                "ruleId": "SKILL:network,egress",
                                "message": {"text": "Calls external API\nreview required"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "skills/api:egress/SKILL.md"},
                                            "region": {"startLine": 7},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    annotations = emit_annotations(result, max_annotations=50)

    assert annotations == [
        "::warning file=skills/api%3Aegress/SKILL.md,line=7,title=agent-bom SKILL%3Anetwork%2Cegress::Calls external API%0Areview required"
    ]


def test_emit_annotations_honors_limit(tmp_path):
    result = tmp_path / "skills.json"
    result.write_text(
        json.dumps(
            {
                "report_type": "skills_scan",
                "files": [
                    {
                        "path": "SKILL.md",
                        "audit": {
                            "findings": [
                                {"title": "one", "source_file": "SKILL.md"},
                                {"title": "two", "source_file": "SKILL.md"},
                            ]
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    annotations = emit_annotations(result, max_annotations=1)

    assert len(annotations) == 1
    assert "one" in annotations[0]
