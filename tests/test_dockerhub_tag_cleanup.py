from __future__ import annotations

import urllib.error
import urllib.request

import pytest

from scripts.dockerhub_tag_cleanup import CleanupPlan, DockerHubClient, apply_cleanup, plan_cleanup


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


class _RetryingDockerHubClient:
    def __init__(self, *, never_delete: bool = False) -> None:
        self.delete_calls: list[tuple[str, str]] = []
        self.never_delete = never_delete

    def delete_tag(self, repository: str, tag: str) -> None:
        self.delete_calls.append((repository, tag))

    def list_tags(self, repository: str) -> list[str]:
        delete_attempts = self.delete_calls.count((repository, "0.96.3"))
        if self.never_delete or delete_attempts < 2:
            return ["latest", "0.98.3", "0.96.3"]
        return ["latest", "0.98.3"]


def test_apply_cleanup_retries_accepted_but_unapplied_deletion() -> None:
    client = _RetryingDockerHubClient()
    plan = CleanupPlan(
        repository="agentbom/agent-bom-ui",
        keep=("latest", "0.98.3"),
        delete=("0.96.3",),
    )

    deleted = apply_cleanup(client, [plan], verification_attempts=3, verification_retry_seconds=0)

    assert deleted == 1
    assert client.delete_calls == [
        ("agentbom/agent-bom-ui", "0.96.3"),
        ("agentbom/agent-bom-ui", "0.96.3"),
    ]


def test_apply_cleanup_fails_after_bounded_verification_attempts() -> None:
    client = _RetryingDockerHubClient(never_delete=True)
    plan = CleanupPlan(
        repository="agentbom/agent-bom-ui",
        keep=("latest", "0.98.3"),
        delete=("0.96.3",),
    )

    with pytest.raises(RuntimeError, match="deletion verification failed after 3 attempts"):
        apply_cleanup(client, [plan], verification_attempts=3, verification_retry_seconds=0)

    assert client.delete_calls == [
        ("agentbom/agent-bom-ui", "0.96.3"),
        ("agentbom/agent-bom-ui", "0.96.3"),
        ("agentbom/agent-bom-ui", "0.96.3"),
    ]


def test_delete_tag_is_idempotent_when_tag_is_already_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    client = object.__new__(DockerHubClient)
    client._token = "test-token"

    def missing_tag(*args: object, **kwargs: object) -> None:
        raise urllib.error.HTTPError("https://example.invalid/tag", 404, "Not Found", {}, None)

    monkeypatch.setattr(urllib.request, "urlopen", missing_tag)

    client.delete_tag("agentbom/agent-bom-ui", "0.96.3")
