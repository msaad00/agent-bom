import pytest

from agent_bom.cloud.aws_iam_evaluator import IamDecision, evaluate_identity_policies
from agent_bom.cloud.aws_iam_evidence import normalize_iam_policy_document


def policy(*statements: dict[str, object]):
    return normalize_iam_policy_document({"Statement": list(statements)})


def test_explicit_deny_overrides_allow() -> None:
    result = evaluate_identity_policies(
        [
            policy({"Sid": "broad", "Effect": "Allow", "Action": "s3:*", "Resource": "*"}),
            policy({"Sid": "guard", "Effect": "Deny", "Action": "s3:Delete*", "Resource": "*"}),
        ],
        action="s3:DeleteObject",
        resource="arn:aws:s3:::private/key",
    )
    assert result.decision is IamDecision.EXPLICIT_DENY
    assert result.matched_deny_sids == ("guard",)


def test_action_resource_and_condition_must_all_match() -> None:
    scoped = policy(
        {
            "Sid": "org-read",
            "Effect": "Allow",
            "Action": "s3:Get*",
            "Resource": "arn:aws:s3:::team/*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-good"}},
        }
    )
    allowed = evaluate_identity_policies(
        [scoped],
        action="S3:GetObject",
        resource="arn:aws:s3:::team/a",
        context={"AWS:PrincipalOrgID": "o-good"},
    )
    wrong_resource = evaluate_identity_policies(
        [scoped], action="s3:GetObject", resource="arn:aws:s3:::other/a", context={"aws:PrincipalOrgID": "o-good"}
    )
    assert allowed.decision is IamDecision.ALLOW
    assert wrong_resource.decision is IamDecision.IMPLICIT_DENY


def test_missing_context_and_unsupported_operator_are_indeterminate() -> None:
    conditional = policy(
        {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*", "Condition": {"IpAddress": {"aws:SourceIp": "10.0.0.0/8"}}}
    )
    assert (
        evaluate_identity_policies([conditional], action="kms:Decrypt", resource="arn:aws:kms:us-east-1:1:key/x").decision
        is IamDecision.INDETERMINATE
    )


def test_not_action_not_resource_and_implicit_deny() -> None:
    guarded = policy({"Effect": "Deny", "NotAction": "iam:Get*", "NotResource": "arn:aws:s3:::public/*"})
    assert (
        evaluate_identity_policies([guarded], action="ec2:TerminateInstances", resource="arn:aws:ec2:us-east-1:1:instance/i-1").decision
        is IamDecision.EXPLICIT_DENY
    )
    assert (
        evaluate_identity_policies([guarded], action="iam:GetRole", resource="arn:aws:iam::1:role/a").decision is IamDecision.IMPLICIT_DENY
    )


def test_bool_gated_statement_is_not_scored_as_unconditional_allow() -> None:
    gated = policy(
        {
            "Sid": "mfa-only",
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "*",
            "Condition": {"Bool": {"aws:MultiFactorAuthPresent": True}},
        }
    )
    # No MFA context is supplied: the Bool condition cannot be positively
    # satisfied, so the statement must NOT flatten into an unconditional allow.
    result = evaluate_identity_policies([gated], action="s3:GetObject", resource="arn:aws:s3:::bucket/key")
    assert result.decision is not IamDecision.ALLOW
    assert result.decision is IamDecision.INDETERMINATE

    # With MFA present in context the Bool condition is satisfied → allow.
    with_mfa = evaluate_identity_policies(
        [gated],
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
        context={"aws:MultiFactorAuthPresent": "true"},
    )
    assert with_mfa.decision is IamDecision.ALLOW


def test_partial_policy_can_never_produce_allow() -> None:
    partial = normalize_iam_policy_document(
        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, {"Effect": "Maybe", "Action": "*"}]}
    )
    assert (
        evaluate_identity_policies([partial], action="s3:GetObject", resource="arn:aws:s3:::bucket/key").decision
        is IamDecision.INDETERMINATE
    )


@pytest.mark.parametrize(
    ("operator", "values", "expected", "effect", "decision"),
    [
        ("ForAllValues:StringEquals", ["team", "outside"], ["team"], "Allow", IamDecision.IMPLICIT_DENY),
        ("ForAllValues:StringLike", ["team:reader", "outside"], ["team:*"], "Allow", IamDecision.IMPLICIT_DENY),
        ("ForAllValues:ArnEquals", ["arn:team", "arn:outside"], ["arn:team"], "Allow", IamDecision.IMPLICIT_DENY),
        ("ForAllValues:ArnLike", ["arn:team:reader", "arn:outside"], ["arn:team:*"], "Allow", IamDecision.IMPLICIT_DENY),
        ("ForAnyValue:StringNotEquals", ["team", "outside"], ["team"], "Deny", IamDecision.EXPLICIT_DENY),
        ("ForAnyValue:StringNotLike", ["team:reader", "outside"], ["team:*"], "Deny", IamDecision.EXPLICIT_DENY),
        ("ForAnyValue:ArnNotEquals", ["arn:team", "arn:outside"], ["arn:team"], "Deny", IamDecision.EXPLICIT_DENY),
        ("ForAnyValue:ArnNotLike", ["arn:team:reader", "arn:outside"], ["arn:team:*"], "Deny", IamDecision.EXPLICIT_DENY),
        ("ForAllValues:StringEquals", ["team", "cost"], ["team", "cost"], "Allow", IamDecision.ALLOW),
        ("ForAnyValue:StringEquals", ["team", "outside"], ["team"], "Allow", IamDecision.ALLOW),
        ("ForAllValues:StringNotEquals", ["team", "outside"], ["team"], "Deny", IamDecision.ALLOW),
        ("ForAnyValue:StringNotEquals", ["team", "cost"], ["team", "cost"], "Deny", IamDecision.ALLOW),
    ],
)
def test_multivalue_condition_quantifiers_preserve_allow_and_deny_scope(operator, values, expected, effect, decision) -> None:
    statements = [
        {"Sid": "scoped", "Effect": effect, "Action": "s3:GetObject", "Resource": "*", "Condition": {operator: {"aws:TagKeys": expected}}}
    ]
    if effect == "Deny":
        statements.insert(0, {"Sid": "base", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"})
    result = evaluate_identity_policies(
        [policy(*statements)], action="s3:GetObject", resource="arn:aws:s3:::bucket/key", context={"aws:TagKeys": values}
    )
    assert result.decision is decision
    if decision is IamDecision.EXPLICIT_DENY:
        assert result.matched_deny_sids == ("scoped",)


@pytest.mark.parametrize("operator", ["ForAllValues:StringEquals", "ForAnyValue:StringNotEquals"])
def test_multivalue_condition_missing_context_remains_unknown(operator) -> None:
    scoped = policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {operator: {"aws:TagKeys": ["team"]}}})
    result = evaluate_identity_policies([scoped], action="s3:GetObject", resource="arn:aws:s3:::bucket/key")
    assert result.decision is IamDecision.INDETERMINATE


@pytest.mark.parametrize(
    ("operator", "decision"), [("ForAllValues:StringEquals", IamDecision.ALLOW), ("ForAnyValue:StringEquals", IamDecision.IMPLICIT_DENY)]
)
def test_explicit_empty_multivalue_context_uses_set_semantics(operator, decision) -> None:
    scoped = policy({"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {operator: {"aws:TagKeys": ["team"]}}})
    result = evaluate_identity_policies([scoped], action="s3:GetObject", resource="arn:aws:s3:::bucket/key", context={"aws:TagKeys": []})
    assert result.decision is decision


@pytest.mark.parametrize(
    "condition",
    [
        None,
        [],
        "guard",
        {},
        {"StringEquals": []},
        {"StringEquals": {}},
        {"StringEquals": {"aws:PrincipalTag/team": []}},
        {"StringEquals": {"aws:PrincipalTag/team": ["team", {"unexpected": "object"}]}},
        {"StringEquals": {"aws:PrincipalTag/team": "team"}, "Bool": {"aws:MultiFactorAuthPresent": {"unexpected": True}}},
        {"": {"aws:TagKeys": "team"}},
        {"StringEquals": {"": "team"}},
    ],
)
@pytest.mark.parametrize("effect", ["Allow", "Deny"])
def test_malformed_condition_never_becomes_an_unconditional_decision(condition, effect) -> None:
    guarded = policy({"Sid": "guarded", "Effect": effect, "Action": "s3:GetObject", "Resource": "*", "Condition": condition})
    # An incomplete deny cannot be discarded while another policy grants access.
    policies = [guarded]
    if effect == "Deny":
        policies.append(policy({"Sid": "allow", "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}))
    result = evaluate_identity_policies(
        policies, action="s3:GetObject", resource="arn:aws:s3:::bucket/key", context={"aws:PrincipalTag/team": "team"}
    )
    assert result.decision is IamDecision.INDETERMINATE
    assert "statement_0_invalid_condition" in guarded.diagnostics


def test_valid_explicit_deny_remains_authoritative_alongside_malformed_condition() -> None:
    result = evaluate_identity_policies(
        [
            policy(
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*", "Condition": {"Bool": {}}},
                {"Sid": "deny", "Effect": "Deny", "Action": "s3:GetObject", "Resource": "*"},
            )
        ],
        action="s3:GetObject",
        resource="arn:aws:s3:::bucket/key",
    )
    assert result.decision is IamDecision.EXPLICIT_DENY
    assert result.matched_deny_sids == ("deny",)
