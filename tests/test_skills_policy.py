"""Policy evaluator tests for skills scans."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from agent_bom.parsers.skill_audit import SkillFinding
from agent_bom.skills_policy import SkillsPolicyError, evaluate_skills_policy


def _enum(value: str) -> SimpleNamespace:
    return SimpleNamespace(value=value)


def _report(*findings: SkillFinding, path: str = "SKILL.md", review: str = "review", content: str = "benign") -> SimpleNamespace:
    return SimpleNamespace(
        files=[
            SimpleNamespace(
                path=path,
                trust=SimpleNamespace(
                    verdict=_enum(content),
                    content_verdict=_enum(content),
                    review_verdict=_enum(review),
                    provenance_verdict=_enum("unverified"),
                ),
                audit=SimpleNamespace(findings=list(findings)),
            )
        ]
    )


def test_skills_policy_warns_on_review_threshold() -> None:
    result = evaluate_skills_policy(_report(), warn_on_review_verdict="review")

    assert result.status == "warn"
    assert not result.failed
    assert result.warnings[0].reason == "review verdict review reached warn threshold review"


def test_skills_policy_fails_on_blocked_review_threshold() -> None:
    result = evaluate_skills_policy(_report(review="blocked"), fail_on_review_verdict="high_risk")

    assert result.status == "fail"
    assert result.failed
    assert result.violations[0].reason == "review verdict blocked reached fail threshold high_risk"


def test_skills_policy_rule_matches_finding_category() -> None:
    finding = SkillFinding(
        severity="high",
        category="prompt_coercion",
        title="Guardrail override",
        detail="bypass the guardrails",
        source_file="SKILL.md",
    )
    policy = {
        "rules": [
            {
                "id": "block-prompt-coercion",
                "action": "block",
                "match": {"category": "prompt_coercion"},
                "reason": "Prompt coercion is not allowed in production skills.",
            }
        ]
    }

    result = evaluate_skills_policy(_report(finding), policy=policy)

    assert result.status == "fail"
    assert result.violations[0].rule_id == "block-prompt-coercion"
    assert result.violations[0].category == "prompt_coercion"
    assert result.violations[0].fingerprint


def test_skills_policy_requires_owned_unexpired_suppression() -> None:
    finding = SkillFinding(
        severity="medium",
        category="undocumented_network",
        title="Network use is not documented",
        detail="https://example.com is referenced without frontmatter",
        source_file="SKILL.md",
    )
    policy = {
        "rules": [{"id": "warn-network", "action": "warn", "match": {"category": "undocumented_network"}}],
        "suppressions": [
            {
                "owner": "security",
                "reason": "Documented in downstream policy",
                "expires": "2999-01-01",
                "match": {"category": "undocumented_network"},
            }
        ],
    }

    result = evaluate_skills_policy(_report(finding), policy=policy)

    assert result.status == "pass"
    assert result.suppressions_applied == 1


def test_skills_policy_rejects_unknown_threshold() -> None:
    with pytest.raises(SkillsPolicyError, match="unknown review verdict threshold"):
        evaluate_skills_policy(_report(), fail_on_review_verdict="maybe")
