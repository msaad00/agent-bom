"""Cross-environment correlation tests (#1892 Phase 1: AWS Bedrock).

The matcher in :mod:`agent_bom.cross_env_correlation` ships under a strict
bar: a ``CORRELATES_WITH`` edge requires the local agent and the cloud agent
to agree on the **full triplet** of strong identity signals — cloud account
ID, region, and model ID. Anything weaker stays in the ``POSSIBLY_CORRELATES_WITH``
lane so reviewers can see candidates without the platform pretending they are
the same agent. PR #1994 was closed because earlier matchers did not respect
this bar; these tests lock the bar in place.
"""

from __future__ import annotations

from agent_bom.cross_env_correlation import (
    CorrelationConfidence,
    correlate_bedrock,
    correlate_cross_environment,
)

_BEDROCK_ARN = "arn:aws:bedrock:us-east-1:111122223333:agent/AGENTID01"
_MODEL = "anthropic.claude-3-5-sonnet-20241022-v2:0"
_OTHER_MODEL = "amazon.titan-text-express-v1"


def _local_agent(
    *,
    name: str = "cursor-dev",
    account_id: str | None = "111122223333",
    region: str | None = "us-east-1",
    model_id: str | None = _MODEL,
    extra_env: dict[str, str] | None = None,
) -> dict:
    env: dict[str, str] = {}
    if account_id is not None:
        env["AWS_ACCOUNT_ID"] = account_id
    if region is not None:
        env["AWS_REGION"] = region
    if model_id is not None:
        env["BEDROCK_MODEL_ID"] = model_id
    if extra_env:
        env.update(extra_env)
    return {
        "name": name,
        "agent_type": "cursor",
        "config_path": "/home/dev/.cursor/mcp.json",
        "version": "0.42.0",
        "metadata": {},
        "mcp_servers": [{"name": "bedrock-mcp", "env": env}],
    }


def _cloud_bedrock_agent(
    *,
    name: str = "bedrock:prod-agent",
    arn: str = _BEDROCK_ARN,
    model_id: str = _MODEL,
    region: str = "us-east-1",
    account_id: str = "111122223333",
) -> dict:
    return {
        "name": name,
        "agent_type": "custom",
        "config_path": arn,
        "source": "aws-bedrock",
        "version": model_id,
        "metadata": {
            "cloud_origin": {
                "provider": "aws",
                "service": "bedrock",
                "resource_type": "agent",
                "resource_id": arn,
                "resource_name": name.split(":", 1)[-1],
                "location": region,
                "scope": {"account_id": account_id} if account_id else {},
            }
        },
        "mcp_servers": [],
    }


def test_full_triplet_match_is_high_confidence() -> None:
    matches = correlate_bedrock([_local_agent(), _cloud_bedrock_agent()])

    assert len(matches) == 1
    match = matches[0]
    assert match.confidence is CorrelationConfidence.HIGH
    assert set(match.matched_signals) == {"account_id", "region", "model_id"}
    assert match.cloud_account_id == "111122223333"
    assert match.cloud_region == "us-east-1"
    assert match.cloud_model_id == _MODEL
    assert match.cloud_provider == "aws"
    assert match.cloud_service == "bedrock"
    assert "Strong triplet" in match.rationale


def test_only_model_id_matches_is_low_confidence() -> None:
    # Same model ID, different account, different region — the case PR #1994
    # was rejected for. Must be visible as a low-confidence candidate, never
    # as the strong CORRELATES_WITH edge.
    local = _local_agent(account_id="999988887777", region="eu-west-1")

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    match = matches[0]
    assert match.confidence is CorrelationConfidence.LOW
    assert match.matched_signals == ("model_id",)
    assert "Partial match" in match.rationale


def test_account_and_region_without_model_is_low_confidence() -> None:
    # The local agent declares the right AWS scope but does not name the
    # specific model — still a low-confidence candidate, not a strong match.
    local = _local_agent(model_id=None)

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    match = matches[0]
    assert match.confidence is CorrelationConfidence.LOW
    assert set(match.matched_signals) == {"account_id", "region"}


def test_sdk_presence_alone_is_not_a_match() -> None:
    # Local agent only signals "I have AWS env set" with no Bedrock-shaped
    # account, region, or model values. The matcher must not emit any edge —
    # the bar from PR #1994 is exactly this case.
    local = _local_agent(
        account_id=None,
        region=None,
        model_id=None,
        extra_env={"AWS_PROFILE": "dev", "AWS_SDK_LOAD_CONFIG": "1"},
    )

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert matches == []


def test_no_cross_account_false_match_when_only_region_matches() -> None:
    # Both have us-east-1 but different account IDs and unrelated models.
    # Region-only is a single weak signal; the matcher must not treat the
    # local agent as related to a totally different account's model.
    local = _local_agent(
        account_id="999988887777",
        region="us-east-1",
        model_id=_OTHER_MODEL,
    )

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    assert matches[0].confidence is CorrelationConfidence.LOW
    assert matches[0].matched_signals == ("region",)


def test_endpoint_url_supplies_region_when_aws_region_is_absent() -> None:
    local = _local_agent(region=None, extra_env={"AWS_ENDPOINT_URL_BEDROCK": "https://bedrock-runtime.us-east-1.amazonaws.com"})

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    match = matches[0]
    assert match.confidence is CorrelationConfidence.HIGH
    assert "region" in match.matched_signals


def test_account_id_must_be_twelve_digits() -> None:
    # A twelve-character non-numeric env value is not an AWS account ID.
    local = _local_agent(account_id="abcdefghijkl")

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    assert matches[0].confidence is CorrelationConfidence.LOW
    assert "account_id" not in matches[0].matched_signals


def test_unknown_vendor_model_string_is_not_treated_as_bedrock_id() -> None:
    # A free-text "claude" string is not a valid Bedrock model id (no vendor
    # prefix). The matcher must reject it so substring tricks don't sneak in.
    local = _local_agent(model_id="claude")

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    assert matches[0].confidence is CorrelationConfidence.LOW
    assert "model_id" not in matches[0].matched_signals


def test_cross_environment_orchestrator_returns_typed_result() -> None:
    result = correlate_cross_environment([_local_agent(), _cloud_bedrock_agent()])

    high = result.by_confidence(CorrelationConfidence.HIGH)
    assert len(high) == 1
    low = result.by_confidence(CorrelationConfidence.LOW)
    assert low == ()


def test_metadata_aws_block_supplies_signals_when_env_is_absent() -> None:
    local = {
        "name": "ci-pipeline",
        "agent_type": "custom",
        "config_path": "/repo/.github/workflows/deploy.yml",
        "version": "",
        "metadata": {
            "aws": {
                "account_id": "111122223333",
                "region": "us-east-1",
                "bedrock_model_id": _MODEL,
            }
        },
        "mcp_servers": [],
    }

    matches = correlate_bedrock([local, _cloud_bedrock_agent()])

    assert len(matches) == 1
    assert matches[0].confidence is CorrelationConfidence.HIGH
