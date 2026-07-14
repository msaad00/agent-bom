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


def test_partial_policy_can_never_produce_allow() -> None:
    partial = normalize_iam_policy_document(
        {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}, {"Effect": "Maybe", "Action": "*"}]}
    )
    assert (
        evaluate_identity_policies([partial], action="s3:GetObject", resource="arn:aws:s3:::bucket/key").decision
        is IamDecision.INDETERMINATE
    )
