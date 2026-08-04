"""The demo estate's central claim, asserted as a chain rather than a count.

A findings count proves nothing. What the product claims is that a finding
resolves to an inventoried asset, that the asset carries identity and
configuration context, that the finding sits on a correlated attack path, and
that it evidences a compliance control. Every test here walks that chain and
fails if any link is a stub.
"""

from __future__ import annotations

import pytest

from agent_bom.demo_estate.enterprise import EnterpriseEstate
from agent_bom.demo_estate.enterprise_composition import build_demo_estate
from agent_bom.demo_estate.enterprise_correlation import (
    build_estate_correlations,
    correlate_enterprise_estate,
)
from agent_bom.demo_estate.enterprise_findings import (
    ESTATE_FINDING_SEVERITY_BUCKETS,
    IDENTITY_RESOURCE_TYPES,
    build_estate_findings,
    summarize_estate_findings,
)
from agent_bom.finding import Finding, FindingSource, FindingType

TENANT = "estate-findings-tenant"


@pytest.fixture(scope="module")
def estate() -> EnterpriseEstate:
    return build_demo_estate(tenant_id=TENANT)


@pytest.fixture(scope="module")
def findings(estate: EnterpriseEstate) -> tuple[Finding, ...]:
    return build_estate_findings(estate)


# ── Link 1: the finding resolves to an asset the estate actually inventoried ──


def test_every_finding_resolves_to_an_inventoried_estate_asset(estate, findings):
    assert findings, "the demo estate produced no findings at all"
    inventoried = {asset.asset_id for asset in estate.assets}
    dangling = sorted({f.asset.identifier or "" for f in findings} - inventoried)
    assert dangling == [], f"findings reference assets the estate does not inventory: {dangling[:5]}"


def test_findings_reuse_the_inventory_asset_id_and_never_a_stub(estate, findings):
    """One id scheme. The estate's ``asset_id`` is the join key, end to end.

    ``cloud_cis_check_to_finding`` falls back to a synthetic ``<provider>-account``
    identifier when a check names no resource. A finding on that stub resolves to
    nothing, which is the exact defect #4637 closed.
    """
    by_id = {asset.asset_id: asset for asset in estate.assets}
    for finding in findings:
        identifier = finding.asset.identifier
        assert identifier in by_id, f"{finding.id} targets a stub asset {identifier!r}"
        asset = by_id[identifier]
        # The canonical id must be a pure function of the inventory asset id, so
        # every finding on one asset joins to the same node.
        assert (
            finding.asset.canonical_id
            == Finding(
                finding_type=FindingType.CIS_FAIL,
                source=FindingSource.CLOUD_CIS,
                asset=type(finding.asset)(name=asset.asset_id, asset_type="cloud_resource", identifier=asset.asset_id),
                severity="medium",
                title="probe",
            ).asset.canonical_id
        )
        assert finding.provider == asset.provider
        assert finding.account_ref and asset.account_scope in finding.account_ref
        assert finding.environment == asset.environment


def test_one_asset_yields_one_canonical_asset_id_across_all_its_findings(findings):
    by_identifier: dict[str, set[str]] = {}
    for finding in findings:
        by_identifier.setdefault(finding.asset.identifier or "", set()).add(finding.asset.canonical_id)
    split = {key: ids for key, ids in by_identifier.items() if len(ids) > 1}
    assert split == {}, f"assets with more than one canonical id: {list(split)[:3]}"


# ── Link 2: the asset carries an identity edge and a configuration edge ──────


def test_every_finding_carries_an_identity_edge_backed_by_the_estate(estate, findings):
    """Both halves of the identity edge must be real, and at least one present.

    ``identity_asset_id`` is an inventoried principal inside the SAME account
    boundary — borrowing one from a neighbouring account would draw an edge that
    does not exist. ``identity_actor_id`` is a principal the estate's own
    evidence observed acting on this very asset. A finding with neither is a
    posture note, not a correlated finding.
    """
    by_id = {asset.asset_id: asset for asset in estate.assets}
    actors_by_asset: dict[str, set[str]] = {}
    for event in estate.observations:
        for resource_id in event.resource_ids:
            actors_by_asset.setdefault(resource_id, set()).add(event.actor_id)

    saw_inventory_identity = False
    saw_observed_actor = False
    for finding in findings:
        subject = by_id[finding.asset.identifier or ""]
        identity_id = finding.evidence.get("identity_asset_id")
        actor_id = finding.evidence.get("identity_actor_id")
        assert identity_id or actor_id, f"{finding.id} has no identity edge at all"

        if identity_id:
            saw_inventory_identity = True
            identity = by_id.get(identity_id)
            assert identity is not None, f"{finding.id} names an identity outside the inventory: {identity_id}"
            assert identity.resource_type in IDENTITY_RESOURCE_TYPES
            assert identity.provider == subject.provider
            assert identity.account_scope == subject.account_scope, (
                f"{finding.id} crosses an account boundary: {identity.account_scope} != {subject.account_scope}"
            )
        if actor_id:
            saw_observed_actor = True
            assert actor_id in actors_by_asset.get(subject.asset_id, set()), (
                f"{finding.id} claims actor {actor_id} that the estate never observed on {subject.asset_id}"
            )

    assert saw_inventory_identity, "no finding resolves to an inventoried identity"
    assert saw_observed_actor, "no finding resolves to an observed principal"


def test_the_phi_data_surfaces_on_the_attack_path_carry_findings(estate, findings):
    """The regulated-data assets are the point of the story; they must not fall out.

    An account that happens to inventory no identity asset must not silently
    drop its findings — that is how the PHI table at the end of the incident
    chain quietly disappeared from the demo.
    """
    by_id = {asset.asset_id: asset for asset in estate.assets}
    affected = {f.asset.identifier for f in findings}
    regulated = {
        asset.asset_id for asset in estate.assets if {"phi", "pii"} & set(asset.data_classifications) and asset.asset_id in affected
    }
    assert regulated, "not one PHI/PII asset in the estate carries a finding"
    assert "snowflake:table:nh_prod/analytics/phi/patient_summary" in affected, (
        f"the incident chain's PHI table has no finding; affected regulated assets={sorted(regulated)[:3]}"
    )
    assert by_id["snowflake:table:nh_prod/analytics/phi/patient_summary"].data_classifications


def test_every_finding_carries_a_configuration_edge_with_observed_and_expected(findings):
    for finding in findings:
        configuration = finding.evidence.get("configuration")
        assert isinstance(configuration, dict), f"{finding.id} has no configuration evidence"
        for key in ("setting", "observed", "expected"):
            assert str(configuration.get(key) or "").strip(), f"{finding.id} configuration is missing {key}"
        assert configuration["observed"] != configuration["expected"], (
            f"{finding.id} reports a misconfiguration whose observed state already matches the expectation"
        )


# ── Link 3: the finding sits on a correlated attack path ─────────────────────


def test_the_incident_chain_assets_carry_findings_linked_to_their_attack_path(estate, findings):
    correlation = next(row for row in correlate_enterprise_estate(estate).correlations if row.kind == "data_egress_attempt")
    on_path = {f.asset.identifier for f in findings} & set(correlation.asset_path)
    assert on_path, f"no finding lands on the primary attack path — the incident chain is still a diagram, path={correlation.asset_path}"
    linked = [f for f in findings if f.asset.identifier in on_path and f.evidence.get("correlation_id") == correlation.correlation_id]
    assert linked, "findings on the attack path do not reference the correlation that makes it a path"
    for finding in linked:
        assert finding.evidence.get("attack_path"), f"{finding.id} claims a correlation but carries no path"
        assert finding.asset.identifier in finding.evidence["attack_path"]


# ── Link 4: the finding evidences a compliance control ───────────────────────


def test_every_finding_maps_to_at_least_one_compliance_control(findings):
    for finding in findings:
        controls = finding.normalized_controls()
        assert controls, f"{finding.id} evidences no compliance control"
        assert finding.applicable_frameworks, f"{finding.id} was never classified by the compliance hub"


def test_findings_evidence_more_than_one_framework_across_the_estate(findings):
    frameworks = {tag.framework for finding in findings for tag in finding.normalized_controls()}
    assert "mitre_attack" in frameworks, f"no ATT&CK technique was tagged across the whole estate; frameworks={sorted(frameworks)}"
    assert len(frameworks) >= 2, f"only one framework is evidenced: {sorted(frameworks)}"


# ── Honest counts ────────────────────────────────────────────────────────────


def test_severity_distribution_is_realistic_and_never_one_band(findings):
    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    assert len(counts) >= 3, f"the estate has only {len(counts)} severity bands: {counts}"
    dominant = max(counts.values()) / len(findings)
    assert dominant <= 0.6, f"one severity band covers {dominant:.0%} of the estate: {counts}"


def test_unrated_severity_is_an_explicit_bucket_and_never_a_silent_drop(estate, findings):
    summary = summarize_estate_findings(estate, findings)
    assert set(summary.by_severity) == set(ESTATE_FINDING_SEVERITY_BUCKETS)
    assert summary.by_severity["unrated"] > 0, (
        "no unrated finding exists, so the demo cannot show that an unevaluable control is reported rather than dropped"
    )
    assert sum(summary.by_severity.values()) == summary.total == len(findings)


def test_summary_reconciles_with_the_findings_it_summarizes(estate, findings):
    summary = summarize_estate_findings(estate, findings)
    assert summary.total == len(findings)
    assert summary.assets_affected == len({f.asset.identifier for f in findings})
    assert summary.assets_total == len(estate.assets)
    assert summary.assets_affected < summary.assets_total, "every asset is affected — that is a labelling exercise, not a posture"
    assert summary.controls_evidenced == len({(tag.framework, tag.control) for f in findings for tag in f.normalized_controls()})
    assert summary.attack_paths_evidenced == len({f.evidence["correlation_id"] for f in findings if f.evidence.get("correlation_id")})


# ── Contract: deterministic, synthetic-labelled, tenant-scoped ───────────────


def test_the_fast_correlation_path_is_not_a_second_derivation(estate):
    """The payload-free correlation must equal the normalizing one, field for field.

    Findings correlate without normalizing 6k payloads they never read. That is
    only safe while both paths produce identical correlations — the moment they
    diverge, the attack path a finding cites stops being the attack path the
    story shows.
    """
    fast = build_estate_correlations(estate)
    full = correlate_enterprise_estate(estate).correlations
    assert [row.model_dump(mode="json") for row in fast] == [row.model_dump(mode="json") for row in full]


def test_tampered_evidence_never_reaches_the_fast_correlation_path(estate):
    tampered = estate.observations[0].model_copy(update={"event_type": "TamperedEvent"})
    broken = estate.model_copy(update={"observations": (tampered, *estate.observations[1:])})
    with pytest.raises(ValueError, match="evidence hash mismatch"):
        build_estate_correlations(broken)


def test_generation_is_deterministic(estate):
    first = build_estate_findings(estate)
    second = build_estate_findings(estate)
    assert [f.id for f in first] == [f.id for f in second]
    assert [f.severity for f in first] == [f.severity for f in second]


def test_findings_are_labelled_synthetic_and_carry_the_estate_tenant(estate, findings):
    for finding in findings:
        assert finding.evidence.get("synthetic") is True, f"{finding.id} is not labelled synthetic"
        assert finding.evidence.get("tenant_id") == estate.tenant_id
        assert finding.evidence.get("estate_id") == estate.estate_id


# ── The bounded story never reports a page size as a total ───────────────────


def test_the_story_bounds_the_list_but_reports_the_unbounded_total():
    from agent_bom.demo_estate.presentation import build_enterprise_demo_story

    story = build_enterprise_demo_story(tenant_id=TENANT)
    truth = build_estate_findings(build_demo_estate(tenant_id=TENANT))

    assert story.finding_summary.total == len(truth)
    assert story.summary.findings == len(truth)
    assert len(story.findings) < story.finding_summary.total, "the story is not actually bounded, so it proves nothing about bounding"
    assert sum(story.finding_summary.by_severity.values()) == story.finding_summary.total


def test_the_bounded_page_leads_with_the_incident_not_an_arbitrary_slice():
    from agent_bom.demo_estate.presentation import build_enterprise_demo_story

    story = build_enterprise_demo_story(tenant_id=TENANT)
    assert story.findings, "the story renders no findings at all"
    assert story.findings[0].correlation_id, "the first row is not on a correlated attack path"
    assert story.findings[0].attack_path
    # Every rendered row is a complete chain — no half-populated placeholder rows.
    for view in story.findings:
        assert view.asset_id and view.asset_canonical_id
        assert view.asset_display_name, f"{view.finding_id} renders an asset with no name"
        assert view.identity_asset_id or view.identity_actor_id
        assert view.identity_display_name or view.identity_actor_id
        assert view.configuration_setting and view.configuration_expected
        assert view.controls
        assert view.severity_bucket in ESTATE_FINDING_SEVERITY_BUCKETS


# ── The demo speaks the product's control vocabulary, not its own ────────────


def test_every_demo_check_still_exists_in_the_shipped_benchmark_scanner():
    """Pin the demo catalog to the real one, so a renumbered control fails here.

    Inventing plausible-looking check ids would make the demo show a control
    vocabulary the product does not implement — a prospect who searched for one
    of them in a real scan would find nothing. Every entry is copied from the
    shipped scanner, and this test is what keeps the copy honest.
    """
    from pathlib import Path

    import agent_bom.cloud as cloud_pkg
    from agent_bom.demo_estate.enterprise_findings import _CATALOG

    sources = {
        provider: (Path(cloud_pkg.__file__).parent / f"{provider}_cis_benchmark.py").read_text(encoding="utf-8")
        for provider in {check.provider for check in _CATALOG}
    }
    drifted = [
        f"{check.provider} {check.check_id} ({check.title})"
        for check in _CATALOG
        if f'check_id="{check.check_id}"' not in sources[check.provider] or f'title="{check.title}"' not in sources[check.provider]
    ]
    assert drifted == [], f"demo checks no longer match the shipped benchmark scanner: {drifted}"


def test_attack_techniques_come_from_the_products_own_cis_tagger(findings):
    """ATT&CK tags must be resolvable by the shipped tagger, not hand-written.

    A frozen technique list would drift from the catalog the product ships the
    moment that catalog moved, and the demo would then claim coverage the
    product cannot reproduce.
    """
    from agent_bom.mitre_attack import get_bundled_attack_techniques

    catalog = set(get_bundled_attack_techniques())
    tagged = {tag.control for f in findings for tag in f.normalized_controls() if tag.framework == "mitre_attack"}
    assert tagged, "no ATT&CK technique was tagged anywhere in the estate"
    assert tagged <= catalog, f"techniques outside the bundled catalog: {sorted(tagged - catalog)[:5]}"


def test_a_second_tenant_gets_its_own_scoped_findings():
    other = build_demo_estate(tenant_id="other-tenant")
    other_findings = build_estate_findings(other)
    assert other_findings, "the second tenant produced no findings"
    assert {f.evidence["tenant_id"] for f in other_findings} == {"other-tenant"}


# ── Adversarial: the estate is identical for every tenant, by design ─────────


def test_two_tenants_holding_identical_finding_ids_both_persist():
    """Same synthetic estate, same finding ids — neither tenant may be deduped away.

    Every tenant that seeds the demo gets byte-identical findings, because the
    estate itself is identical; the ids collide completely. That makes this the
    cheapest available probe for the defect class where a store dedupes on a
    key that omits ``tenant_id`` and silently drops the second tenant's rows
    while still reporting healthy. It has happened here before.
    """
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore

    left = build_estate_findings(build_demo_estate(tenant_id="tenant-left"))
    right = build_estate_findings(build_demo_estate(tenant_id="tenant-right"))
    left_ids = {f.id for f in left}
    assert left_ids == {f.id for f in right}, "the probe is void unless the ids actually collide"

    store = InMemoryComplianceHubStore()
    for tenant, findings_for_tenant in (("tenant-left", left), ("tenant-right", right)):
        store.upsert_current_batch(
            tenant,
            [f.to_dict() for f in findings_for_tenant],
            observed_at="2026-08-04T00:00:00Z",
            batch_id=f"batch-{tenant}",
            source="demo-estate",
        )

    for tenant in ("tenant-left", "tenant-right"):
        page = store.list_current_page(tenant, limit=1000)
        rows = page[0] if isinstance(page, tuple) else page
        assert len(rows) == len(left_ids), f"{tenant} kept {len(rows)} of {len(left_ids)} findings"

    # And no tenant can see the other's rows.
    other = store.list_current_page("tenant-unseeded", limit=10)
    other_rows = other[0] if isinstance(other, tuple) else other
    assert list(other_rows) == [], "an unseeded tenant sees another tenant's findings"
