"""The demo estate has to look like an enterprise, not one of each thing.

The hand-authored estate is a narrative spine: 20 assets, at most three per
provider, one account per cloud. It proves the contract but cannot show the
product's actual claim — that findings, identities, configuration and logs
correlate across a large multi-vendor estate.

These tests pin the properties that make a generated estate *enterprise-shaped*
rather than merely large: several accounts per cloud, every environment
represented within each provider, and identities that actually resolve to the
resources they touch. Volume alone is not the point; a big flat estate tells the
same thin story as a small one.
"""

from __future__ import annotations

from collections import Counter, defaultdict

import pytest

from agent_bom.demo_estate.enterprise import (
    CollectionStatus,
    EnterpriseEstate,
    EstateStage,
    verify_observation_hash,
)
from agent_bom.demo_estate.enterprise_scale import (
    CLOUD_PROVIDERS,
    MIN_ACCOUNTS_PER_CLOUD,
    MIN_ENTERPRISE_ASSETS,
    MIN_ENTERPRISE_EVENTS,
    MIN_RESOURCES_PER_ACCOUNT,
    ScaleProfile,
    build_scaled_estate,
)

SMALL = ScaleProfile(accounts_per_cloud=2, resources_per_account=6, events_per_asset=1)


@pytest.fixture(scope="module")
def estate() -> EnterpriseEstate:
    return build_scaled_estate(SMALL)


def test_the_generated_estate_satisfies_the_versioned_contract(estate: EnterpriseEstate) -> None:
    """Reuse the contract, never fork it — construction runs every validator."""
    assert isinstance(estate, EnterpriseEstate)
    assert estate.synthetic is True
    assert estate.fictional is True
    assert estate.disclosure


def test_generation_is_deterministic(estate: EnterpriseEstate) -> None:
    """A demo that shifts under you cannot be screenshotted, tested, or trusted."""
    again = build_scaled_estate(SMALL)

    assert again.content_hash == estate.content_hash


def test_a_larger_profile_produces_a_different_estate(estate: EnterpriseEstate) -> None:
    bigger = build_scaled_estate(ScaleProfile(accounts_per_cloud=3, resources_per_account=6, events_per_asset=1))

    assert len(bigger.assets) > len(estate.assets)
    assert bigger.content_hash != estate.content_hash


def test_every_cloud_spans_several_accounts(estate: EnterpriseEstate) -> None:
    """One account per cloud is a diagram, not an estate — drill-down needs siblings."""
    accounts: dict[str, set[str]] = defaultdict(set)
    for asset in estate.assets:
        if asset.provider in CLOUD_PROVIDERS:
            accounts[asset.provider].add(asset.account_scope)

    assert set(accounts) == set(CLOUD_PROVIDERS), f"missing clouds: {set(CLOUD_PROVIDERS) - set(accounts)}"
    thin = {provider: sorted(scopes) for provider, scopes in accounts.items() if len(scopes) < 2}
    assert not thin, f"these clouds have a single account, so account drill-down shows nothing: {thin}"


def test_every_cloud_covers_every_environment(estate: EnterpriseEstate) -> None:
    """Environment was null for AWS/GCP in the real graph; the demo must not repeat it."""
    environments: dict[str, set[str]] = defaultdict(set)
    for asset in estate.assets:
        if asset.provider in CLOUD_PROVIDERS:
            environments[asset.provider].add(asset.environment)

    missing = {
        provider: sorted({"production", "staging", "development"} - envs)
        for provider, envs in environments.items()
        if {"production", "staging", "development"} - envs
    }
    assert not missing, f"providers missing environments: {missing}"


def test_no_asset_leaves_a_scope_dimension_blank(estate: EnterpriseEstate) -> None:
    """A blank dimension silently drops the asset out of every scoped projection."""
    blank = [
        asset.asset_id
        for asset in estate.assets
        if not asset.environment.strip() or not asset.account_scope.strip() or not asset.region.strip()
    ]

    assert not blank, f"assets with a blank scope dimension: {blank[:5]}"


def test_observations_reference_many_distinct_assets(estate: EnterpriseEstate) -> None:
    """Correlation is the claim. Events pointing at a handful of assets do not show it.

    Measured against the *observable* inventory. Some rows have no control plane
    to be observed on: a package appears in an SBOM and in a vulnerability
    finding, never in an audit log, and the organization root is a grouping node.
    Counting them in the denominator would mean the only way to keep this green
    is to emit an audit event for a package — evidence the estate cannot justify.
    """
    touched = {asset_id for event in estate.observations for asset_id in event.resource_ids}
    observable = [
        asset for asset in estate.assets if asset.resource_type not in {"package", "organization"}
    ]

    assert len(touched) >= len(observable) // 2, (
        f"only {len(touched)} of {len(observable)} observable assets carry any evidence"
    )


def test_every_observation_hash_verifies(estate: EnterpriseEstate) -> None:
    unverified = [event.event_id for event in estate.observations if not verify_observation_hash(event)]

    assert not unverified, f"observations whose provenance hash does not verify: {unverified[:5]}"


def test_provenance_never_crosses_the_tenant_boundary(estate: EnterpriseEstate) -> None:
    foreign = {event.provenance.tenant_id for event in estate.observations} - {estate.tenant_id}

    assert not foreign, f"observations carrying a foreign tenant: {sorted(foreign)}"


def test_partial_collection_is_reported_honestly(estate: EnterpriseEstate) -> None:
    """An incomplete read must never serialize as a complete posture."""
    for run in estate.collection_runs:
        if run.status is CollectionStatus.COMPLETE:
            assert not run.failure_code
        else:
            assert run.failure_code, f"{run.source} is {run.status} but carries no failure_code"

    assert any(run.status is not CollectionStatus.COMPLETE for run in estate.collection_runs), (
        "an estate where every collection succeeds cannot demonstrate honest partial evidence"
    )


def test_every_evidence_source_actually_collects(estate: EnterpriseEstate) -> None:
    """A source with a run but no events is a dead stage in the pipeline view."""
    produced = Counter(event.source for event in estate.observations)
    silent = [run.source for run in estate.collection_runs if run.status is CollectionStatus.COMPLETE and not produced.get(run.source)]

    assert not silent, f"sources reporting a complete collection but no evidence: {silent}"


def test_the_estate_tells_a_before_and_after_story(estate: EnterpriseEstate) -> None:
    stages = {snapshot.stage for snapshot in estate.snapshots}

    assert stages == {EstateStage.BASELINE, EstateStage.CURRENT, EstateStage.REMEDIATED}
    for snapshot in estate.snapshots:
        assert snapshot.asset_ids, f"{snapshot.stage} snapshot holds no assets"
        assert snapshot.change_summary.strip()


def test_snapshots_only_reference_assets_that_exist(estate: EnterpriseEstate) -> None:
    known = {asset.asset_id for asset in estate.assets}
    for snapshot in estate.snapshots:
        unknown = set(snapshot.asset_ids) - known
        assert not unknown, f"{snapshot.stage} references unknown assets: {sorted(unknown)[:5]}"


# ---------------------------------------------------------------------------
# Size, not only shape. A correctly-shaped estate that is tiny still cannot show
# correlation, so the shipped default carries a floor as well as a form.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def shipped() -> EnterpriseEstate:
    """The default profile — what a demo actually gets."""
    return build_scaled_estate()


def test_the_shipped_estate_is_enterprise_sized(shipped: EnterpriseEstate) -> None:
    assert len(shipped.assets) >= MIN_ENTERPRISE_ASSETS, (
        f"the shipped estate holds {len(shipped.assets)} assets; below {MIN_ENTERPRISE_ASSETS} it reads as a diagram, not an estate"
    )
    assert len(shipped.observations) >= MIN_ENTERPRISE_EVENTS, (
        f"the shipped estate holds {len(shipped.observations)} events; "
        f"below {MIN_ENTERPRISE_EVENTS} there is too little evidence to correlate"
    )


def test_the_shipped_estate_has_depth_within_each_account(shipped: EnterpriseEstate) -> None:
    """Breadth without depth is still a diagram — each account needs a real population."""
    per_account: dict[tuple[str, str], int] = Counter()
    for asset in shipped.assets:
        if asset.provider in CLOUD_PROVIDERS:
            per_account[(asset.provider, asset.account_scope)] += 1

    accounts_per_cloud: dict[str, int] = Counter(provider for provider, _ in per_account)
    thin_clouds = {p: n for p, n in accounts_per_cloud.items() if n < MIN_ACCOUNTS_PER_CLOUD}
    assert not thin_clouds, f"clouds with fewer than {MIN_ACCOUNTS_PER_CLOUD} accounts: {thin_clouds}"

    thin_accounts = {key: n for key, n in per_account.items() if n < MIN_RESOURCES_PER_ACCOUNT}
    assert not thin_accounts, f"accounts holding fewer than {MIN_RESOURCES_PER_ACCOUNT} resources: {dict(list(thin_accounts.items())[:3])}"


def test_the_shipped_estate_keeps_every_shape_guarantee(shipped: EnterpriseEstate) -> None:
    """Size must not come at the cost of the properties that make it legible."""
    environments: dict[str, set[str]] = defaultdict(set)
    accounts: dict[str, set[str]] = defaultdict(set)
    for asset in shipped.assets:
        if asset.provider in CLOUD_PROVIDERS:
            environments[asset.provider].add(asset.environment)
            accounts[asset.provider].add(asset.account_scope)

    for provider in CLOUD_PROVIDERS:
        assert {"production", "staging", "development"} <= environments[provider], provider
        assert len(accounts[provider]) >= MIN_ACCOUNTS_PER_CLOUD, provider

    unverified = [e.event_id for e in shipped.observations if not verify_observation_hash(e)]
    assert not unverified, f"{len(unverified)} observations fail their own provenance check at scale"
