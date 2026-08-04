"""The demo needs one estate that is both a story and an enterprise.

Two halves existed and neither was enough on its own. The hand-authored estate
carries the incident chain the demo narrates — GitHub to AWS to Kubernetes to
MCP to Snowflake — but is 20 assets, so nothing has to be correlated *out of*
anything. The generator produces thousands of correlated assets but no incident,
so there is nothing to find. It also shipped unused: `build_scaled_estate` had
exactly one consumer, its own test.

Composing them puts the incident inside a population, which is the only
arrangement where "we correlate across a large multi-vendor estate" is
demonstrated rather than asserted.
"""

from __future__ import annotations

from collections import Counter

import pytest

from agent_bom.demo_estate.enterprise import (
    CollectionStatus,
    EnterpriseEstate,
    verify_observation_hash,
)
from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import correlate_enterprise_estate


@pytest.fixture(scope="module")
def estate() -> EnterpriseEstate:
    return build_demo_estate()


def test_the_narrative_survives_composition(estate: EnterpriseEstate) -> None:
    """The story is the point; scale must not dilute it out of existence."""
    result = correlate_enterprise_estate(estate)
    kinds = {row.kind for row in result.correlations}

    assert "data_egress_attempt" in kinds, "the primary incident correlation is gone — presentation.py raises without it"


def test_the_narrative_now_sits_inside_a_population(estate: EnterpriseEstate) -> None:
    assert len(estate.assets) >= 2000
    assert len(estate.observations) >= 6000


def test_every_cloud_has_siblings_to_disambiguate_between(estate: EnterpriseEstate) -> None:
    accounts: dict[str, set[str]] = {}
    for asset in estate.assets:
        if asset.provider in {"aws", "azure", "gcp", "snowflake"}:
            accounts.setdefault(asset.provider, set()).add(asset.account_scope)

    thin = {p: sorted(s) for p, s in accounts.items() if len(s) < 2}
    assert not thin, f"single-account clouds make drill-down meaningless: {thin}"


def test_composition_is_deterministic() -> None:
    assert build_demo_estate().content_hash == build_demo_estate().content_hash


def test_no_identity_collides_between_the_two_halves(estate: EnterpriseEstate) -> None:
    """A generated id shadowing a narrative asset would silently rewrite the story."""
    asset_ids = [a.asset_id for a in estate.assets]
    event_ids = [e.event_id for e in estate.observations]

    assert len(asset_ids) == len(set(asset_ids))
    assert len(event_ids) == len(set(event_ids))


def test_provenance_still_verifies_across_the_whole_estate(estate: EnterpriseEstate) -> None:
    bad = [e.event_id for e in estate.observations if not verify_observation_hash(e)]

    assert not bad, f"{len(bad)} observations fail their own provenance check"


def test_partial_collection_is_still_reported_honestly(estate: EnterpriseEstate) -> None:
    for run in estate.collection_runs:
        if run.status is CollectionStatus.COMPLETE:
            assert not run.failure_code
        else:
            assert run.failure_code

    assert any(r.status is not CollectionStatus.COMPLETE for r in estate.collection_runs)


def test_every_source_that_reports_complete_produced_evidence(estate: EnterpriseEstate) -> None:
    produced = Counter(e.source for e in estate.observations)
    silent = [r.source for r in estate.collection_runs if r.status is CollectionStatus.COMPLETE and not produced.get(r.source)]

    assert not silent, f"sources claiming a complete collection with no evidence: {silent}"


def test_the_story_is_bounded_but_reports_the_unbounded_truth() -> None:
    """A page that reports its own size as the total is the honesty defect we keep finding."""
    from agent_bom.demo_estate.presentation import build_enterprise_demo_story

    story = build_enterprise_demo_story(tenant_id="composition-tenant")

    assert story.summary.correlations > len(story.correlations), "summary must report the estate total, not the page size"
    assert story.summary.observations > len(story.events)
    assert story.correlations[0] == story.primary_correlation, "the incident must lead the view"
    assert story.primary_correlation.kind == "data_egress_attempt"
