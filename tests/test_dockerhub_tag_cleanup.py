from __future__ import annotations

import pytest

from scripts.dockerhub_tag_cleanup import plan_cleanup


def test_plan_keeps_latest_and_highest_semver_tags() -> None:
    plan = plan_cleanup(
        "agentbom/agent-bom-ui",
        ["0.98.1", "latest", "0.96.4", "0.98.3", "0.98.2"],
        keep_count=2,
    )

    assert plan.keep == ("latest", "0.98.3", "0.98.2")
    assert plan.delete == ("0.98.1", "0.96.4")


def test_plan_deletes_stale_major_floating_tag() -> None:
    plan = plan_cleanup(
        "agentbom/agent-bom",
        ["latest", "0", "0.98.3", "0.98.2"],
        keep_count=2,
    )

    assert plan.keep == ("latest", "0.98.3", "0.98.2")
    assert plan.delete == ("0",)


def test_plan_sorts_semver_numerically() -> None:
    plan = plan_cleanup(
        "agentbom/agent-bom",
        ["latest", "0.9.9", "0.10.0", "0.98.3"],
        keep_count=2,
    )

    assert plan.keep == ("latest", "0.98.3", "0.10.0")
    assert plan.delete == ("0.9.9",)


@pytest.mark.parametrize(
    ("tags", "message"),
    [
        (["0.98.3"], "required floating tag 'latest' is missing"),
        (["latest", "sha-deadbeef"], "refusing to delete unexpected tags"),
    ],
)
def test_plan_fails_closed_on_unexpected_registry_state(tags: list[str], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        plan_cleanup("agentbom/agent-bom", tags, keep_count=10)


@pytest.mark.parametrize("keep_count", [0, 51])
def test_plan_rejects_unbounded_retention_values(keep_count: int) -> None:
    with pytest.raises(ValueError, match="keep_count must be between 1 and 50"):
        plan_cleanup("agentbom/agent-bom", ["latest"], keep_count=keep_count)
