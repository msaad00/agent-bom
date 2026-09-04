"""Canonical cross-provider identity/resource join contract."""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jsonschema
import pytest
from pydantic import ValidationError

import agent_bom.identity.join_contract as join_contract_module
from agent_bom.evidence.semantics import (
    CompletenessEntry,
    EvidenceBasis,
    EvidenceCompletenessLedger,
    EvidenceFreshness,
    EvidenceProvenance,
    EvidenceStage,
    EvidenceStatus,
)
from agent_bom.identity.join_contract import (
    CanonicalIdentityEntity,
    CanonicalIdentityType,
    CanonicalResourceReference,
    IdentityJoinMethod,
    IdentityRelationship,
    IdentityRelationshipType,
    IdentityResourceJoinContract,
    IdentitySourceKind,
    ProviderNativeId,
    canonical_identity_relationship_id,
    canonical_provider_native_assertion_id,
)

_EVALUATED_AT = datetime(2026, 9, 4, tzinfo=timezone.utc)
_FRESHNESS_MAX_AGE_SECONDS = 86_400


def _evidence(
    evidence_id: str,
    source: str,
    *,
    basis: EvidenceBasis = EvidenceBasis.OBSERVED,
    status: EvidenceStatus = EvidenceStatus.COMPLETE,
    source_ids: tuple[str, ...] | None = None,
) -> EvidenceProvenance:
    freshness = EvidenceFreshness.evaluate(
        observed_at=_EVALUATED_AT - timedelta(hours=1),
        evaluated_at=_EVALUATED_AT,
        max_age_seconds=_FRESHNESS_MAX_AGE_SECONDS,
    )
    return EvidenceProvenance(
        evidence_id=evidence_id,
        basis=basis,
        status=status,
        source=source,
        source_ids=source_ids or (evidence_id,),
        freshness=freshness,
        reason_codes=() if status is EvidenceStatus.COMPLETE else ("source_incomplete",),
    )


def _native(source: IdentitySourceKind, provider: str, account: str, id_type: str, value: str) -> ProviderNativeId:
    return ProviderNativeId(source=source, provider=provider, account=account, id_type=id_type, value=value)


def _identity(
    entity_id: str,
    entity_type: CanonicalIdentityType,
    native_id: ProviderNativeId,
    evidence_ref: str,
    *,
    display_name: str | None = None,
) -> CanonicalIdentityEntity:
    return CanonicalIdentityEntity(
        entity_id=entity_id,
        entity_type=entity_type,
        display_name=display_name or entity_id,
        native_ids=(native_id,),
        evidence_refs=(evidence_ref,),
    )


def _complete_ledger() -> EvidenceCompletenessLedger:
    return EvidenceCompletenessLedger(
        entries=(
            CompletenessEntry(
                stage=EvidenceStage.COLLECTION,
                component="identity-inventory",
                status=EvidenceStatus.COMPLETE,
                returned_count=6,
                expected_count=6,
            ),
            CompletenessEntry(
                stage=EvidenceStage.GRAPH_JOIN,
                component="identity-resource-join",
                status=EvidenceStatus.COMPLETE,
                returned_count=4,
                expected_count=4,
            ),
        )
    )


def _payload() -> dict:
    return _contract().model_dump(mode="json", exclude_computed_fields=True)


def _bind_native_assertion(contract: dict, *, evidence_id: str, native_id: dict) -> None:
    evidence = next(item for item in contract["evidence"] if item["evidence_id"] == evidence_id)
    evidence["source_ids"].append(canonical_provider_native_assertion_id(ProviderNativeId.model_validate(native_id)))


def _contract() -> IdentityResourceJoinContract:
    membership_assertion = "okta-membership:00uABCDef123:00gEng-Prod"
    workload_assertion = "azure-workload-binding:payments-api"
    trust_assertion = "aws-trust-policy:DeployRole:gcp-scanner"
    owner_assertion = "asset-owner:github-bot:artifact-bucket"
    identities = (
        _identity(
            "identity:person:alice",
            CanonicalIdentityType.PERSON,
            _native(IdentitySourceKind.OKTA, "okta", "okta-org-acme", "user_id", "00uABCDef123"),
            "evidence:okta:1",
            display_name="Alice Example",
        ),
        _identity(
            "identity:group:engineering",
            CanonicalIdentityType.GROUP,
            _native(IdentitySourceKind.OKTA, "okta", "okta-org-acme", "group_id", "00gEng-Prod"),
            "evidence:okta:1",
        ),
        _identity(
            "identity:role:deploy",
            CanonicalIdentityType.ROLE,
            _native(
                IdentitySourceKind.AWS,
                "aws",
                "123456789012",
                "arn",
                "arn:aws:iam::123456789012:role/DeployRole",
            ),
            "evidence:aws:1",
        ),
        _identity(
            "identity:workload:payments",
            CanonicalIdentityType.WORKLOAD_IDENTITY,
            _native(
                IdentitySourceKind.AZURE,
                "azure",
                "subscription-sub-1",
                "principal_id",
                "7D41A138-3028-4B6A-9D21-A61C4E978173",
            ),
            "evidence:azure:1",
        ),
        _identity(
            "identity:service-account:gcp-scanner",
            CanonicalIdentityType.SERVICE_ACCOUNT,
            _native(
                IdentitySourceKind.GCP,
                "gcp",
                "project-1",
                "email",
                "Scanner@project-1.iam.gserviceaccount.com",
            ),
            "evidence:gcp:1",
        ),
        _identity(
            "identity:service-account:github-bot",
            CanonicalIdentityType.SERVICE_ACCOUNT,
            _native(IdentitySourceKind.SAAS, "github", "github-org-acme", "app_id", "Iv1.AbcDEF-123"),
            "evidence:saas:1",
        ),
    )
    resources = (
        CanonicalResourceReference(
            resource_id="resource:azure:payments-api",
            resource_type="container-app",
            display_name="payments-api",
            native_ids=(
                _native(
                    IdentitySourceKind.AZURE,
                    "azure",
                    "subscription-sub-1",
                    "resource_id",
                    "/subscriptions/Sub-1/resourceGroups/Prod/providers/Microsoft.App/containerApps/payments-api",
                ),
            ),
            evidence_refs=("evidence:azure:1",),
        ),
        CanonicalResourceReference(
            resource_id="resource:aws:artifact-bucket",
            resource_type="object-store",
            display_name="artifact-bucket",
            native_ids=(
                _native(
                    IdentitySourceKind.AWS,
                    "aws",
                    "123456789012",
                    "arn",
                    "arn:aws:s3:::Artifact-Bucket-Prod",
                ),
            ),
            evidence_refs=("evidence:aws:1",),
        ),
    )
    evidence = (
        _evidence(
            "evidence:okta:1",
            "okta-scim",
            source_ids=tuple(canonical_provider_native_assertion_id(item.native_ids[0]) for item in identities[:2]),
        ),
        _evidence(
            "evidence:aws:1",
            "aws-iam",
            source_ids=(
                canonical_provider_native_assertion_id(identities[2].native_ids[0]),
                canonical_provider_native_assertion_id(resources[1].native_ids[0]),
            ),
        ),
        _evidence(
            "evidence:azure:1",
            "azure-graph",
            source_ids=(
                canonical_provider_native_assertion_id(identities[3].native_ids[0]),
                canonical_provider_native_assertion_id(resources[0].native_ids[0]),
            ),
        ),
        _evidence(
            "evidence:gcp:1",
            "gcp-iam",
            source_ids=(canonical_provider_native_assertion_id(identities[4].native_ids[0]),),
        ),
        _evidence(
            "evidence:saas:1",
            "github-saas",
            source_ids=(canonical_provider_native_assertion_id(identities[5].native_ids[0]),),
        ),
        _evidence("evidence:okta-membership:1", "okta-membership", source_ids=(membership_assertion,)),
        _evidence("evidence:azure-binding:1", "azure-workload-binding", source_ids=(workload_assertion,)),
        _evidence("evidence:aws-trust:1", "aws-trust-policy", source_ids=(trust_assertion,)),
        _evidence("evidence:asset-owner:1", "asset-owner-catalog", source_ids=(owner_assertion,)),
    )
    relationship_specs = (
        dict(
            relationship_type=IdentityRelationshipType.MEMBER_OF,
            join_method=IdentityJoinMethod.DIRECTORY_MEMBERSHIP,
            source_ref="identity:person:alice",
            target_ref="identity:group:engineering",
            source_native_id=identities[0].native_ids[0],
            target_native_id=identities[1].native_ids[0],
            provider_assertion_ids=(membership_assertion,),
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:okta-membership:1",),
        ),
        dict(
            relationship_type=IdentityRelationshipType.RUNS_AS,
            join_method=IdentityJoinMethod.WORKLOAD_BINDING,
            source_ref="resource:azure:payments-api",
            target_ref="identity:workload:payments",
            source_native_id=resources[0].native_ids[0],
            target_native_id=identities[3].native_ids[0],
            provider_assertion_ids=(workload_assertion,),
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:azure-binding:1",),
        ),
        dict(
            relationship_type=IdentityRelationshipType.TRUSTS,
            join_method=IdentityJoinMethod.TRUST_POLICY,
            source_ref="identity:role:deploy",
            target_ref="identity:service-account:gcp-scanner",
            source_native_id=identities[2].native_ids[0],
            target_native_id=identities[4].native_ids[0],
            provider_assertion_ids=(trust_assertion,),
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:aws-trust:1",),
        ),
        dict(
            relationship_type=IdentityRelationshipType.OWNS,
            join_method=IdentityJoinMethod.OWNERSHIP_RECORD,
            source_ref="identity:service-account:github-bot",
            target_ref="resource:aws:artifact-bucket",
            source_native_id=identities[5].native_ids[0],
            target_native_id=resources[1].native_ids[0],
            provider_assertion_ids=(owner_assertion,),
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:asset-owner:1",),
        ),
    )
    relationships = []
    for spec in relationship_specs:
        relationship = IdentityRelationship(relationship_id="pending", **spec)
        relationships.append(
            relationship.model_copy(
                update={
                    "relationship_id": canonical_identity_relationship_id(
                        tenant_id="tenant-acme",
                        relationship=relationship,
                    )
                }
            )
        )
    return IdentityResourceJoinContract(
        tenant_id="tenant-acme",
        evaluated_at=_EVALUATED_AT,
        freshness_max_age_seconds=_FRESHNESS_MAX_AGE_SECONDS,
        identities=identities,
        resources=resources,
        relationships=tuple(relationships),
        evidence=evidence,
        completeness=_complete_ledger(),
    )


def test_cross_provider_entities_preserve_native_ids_exactly() -> None:
    contract = _contract()

    assert {identity.entity_type for identity in contract.identities} == set(CanonicalIdentityType)
    native_values = {native.value for identity in contract.identities for native in identity.native_ids}
    assert "arn:aws:iam::123456789012:role/DeployRole" in native_values
    assert "7D41A138-3028-4B6A-9D21-A61C4E978173" in native_values
    assert "Scanner@project-1.iam.gserviceaccount.com" in native_values
    assert "Iv1.AbcDEF-123" in native_values


def test_only_complete_observed_structural_joins_are_asserted() -> None:
    contract = _contract()

    assert contract.overall_status is EvidenceStatus.COMPLETE
    assert all(relationship.asserted for relationship in contract.relationships)
    assert {relationship.relationship_type for relationship in contract.relationships} == {
        IdentityRelationshipType.MEMBER_OF,
        IdentityRelationshipType.RUNS_AS,
        IdentityRelationshipType.TRUSTS,
        IdentityRelationshipType.OWNS,
    }


@pytest.mark.parametrize("status", [EvidenceStatus.PARTIAL, EvidenceStatus.UNAVAILABLE])
def test_incomplete_join_attempts_are_explicit_non_edges(status: EvidenceStatus) -> None:
    relationship = IdentityRelationship(
        relationship_id=f"join:attempt:{status.value}",
        relationship_type=IdentityRelationshipType.ASSUMES,
        join_method=IdentityJoinMethod.ROLE_ASSIGNMENT,
        source_ref="identity:person:alice",
        target_ref=None,
        status=status,
        evidence_refs=("evidence:okta:1",) if status is EvidenceStatus.PARTIAL else (),
        reason_codes=("authoritative_target_id_missing",),
    )

    assert relationship.asserted is False
    assert relationship.status is status


def test_incomplete_join_requires_a_bounded_reason() -> None:
    with pytest.raises(ValidationError, match="reason"):
        IdentityRelationship(
            relationship_id="join:attempt:missing-reason",
            relationship_type=IdentityRelationshipType.ASSUMES,
            join_method=IdentityJoinMethod.ROLE_ASSIGNMENT,
            source_ref="identity:person:alice",
            status=EvidenceStatus.UNAVAILABLE,
        )


def test_permission_join_vocabulary_is_intentionally_absent() -> None:
    payload = {
        "relationship_id": "join:forbidden:permission",
        "relationship_type": "has_permission",
        "source_ref": "identity:person:alice",
        "target_ref": "resource:aws:artifact-bucket",
        "status": "complete",
        "evidence_refs": ["evidence:aws:1"],
    }

    with pytest.raises(ValidationError):
        IdentityRelationship.model_validate(payload)


def test_complete_join_rejects_inferred_or_modeled_evidence() -> None:
    contract = _payload()
    membership_evidence = next(item for item in contract["evidence"] if item["evidence_id"] == "evidence:okta-membership:1")
    membership_evidence["basis"] = "inferred"

    with pytest.raises(ValidationError, match="directly observed"):
        IdentityResourceJoinContract.model_validate(contract)


def test_duplicate_provider_native_id_cannot_resolve_to_two_entities() -> None:
    contract = _payload()
    duplicate = dict(contract["identities"][0])
    duplicate["entity_id"] = "identity:person:alice-duplicate"
    contract["identities"].append(duplicate)

    with pytest.raises(ValidationError, match="provider-native identity"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_references_must_resolve_inside_the_contract() -> None:
    contract = _payload()
    contract["relationships"][0]["target_ref"] = "identity:group:missing"

    with pytest.raises(ValidationError, match="unknown canonical endpoint"):
        IdentityResourceJoinContract.model_validate(contract)


def test_join_direction_is_validated_by_relationship_type() -> None:
    contract = _payload()
    contract["relationships"][0]["source_ref"] = "resource:aws:artifact-bucket"

    with pytest.raises(ValidationError, match="member_of"):
        IdentityResourceJoinContract.model_validate(contract)


def test_public_schema_exposes_closed_types_and_explicit_evidence_states() -> None:
    from agent_bom.api.models import IdentityResourceJoinContract as PublicContract

    schema = PublicContract.model_json_schema()
    definitions = schema["$defs"]
    assert definitions["CanonicalIdentityType"]["enum"] == [
        "person",
        "service_account",
        "workload_identity",
        "role",
        "group",
    ]
    assert definitions["IdentitySourceKind"]["enum"] == ["okta", "aws", "azure", "gcp", "saas"]
    assert definitions["EvidenceStatus"]["enum"] == ["complete", "partial", "unavailable", "failed"]
    assert "has_permission" not in definitions["IdentityRelationshipType"]["enum"]
    assert schema["additionalProperties"] is False


def test_account_is_part_of_provider_native_identity_scope() -> None:
    contract = _payload()
    account_a = deepcopy(contract["identities"][0])
    account_a["entity_id"] = "identity:person:alice-in-org-a"
    account_a["native_ids"][0]["account"] = "okta-org-a"
    account_b = deepcopy(contract["identities"][0])
    account_b["entity_id"] = "identity:person:alice-in-org-b"
    account_b["native_ids"][0]["account"] = "okta-org-b"
    contract["identities"].extend((account_a, account_b))
    _bind_native_assertion(contract, evidence_id="evidence:okta:1", native_id=account_a["native_ids"][0])
    _bind_native_assertion(contract, evidence_id="evidence:okta:1", native_id=account_b["native_ids"][0])

    validated = IdentityResourceJoinContract.model_validate(contract)

    assert len(validated.identities) == 8


def test_provider_native_resource_cannot_resolve_to_two_resources() -> None:
    contract = _payload()
    duplicate = deepcopy(contract["resources"][0])
    duplicate["resource_id"] = "resource:azure:payments-api-duplicate"
    contract["resources"].append(duplicate)

    with pytest.raises(ValidationError, match="provider-native resource"):
        IdentityResourceJoinContract.model_validate(contract)


def test_provider_native_id_cannot_resolve_to_both_identity_and_resource() -> None:
    contract = _payload()
    shared_native_id = deepcopy(contract["identities"][0]["native_ids"][0])
    contract["resources"][0]["native_ids"] = [shared_native_id]
    contract["resources"][0]["evidence_refs"] = contract["identities"][0]["evidence_refs"]
    contract["relationships"] = []

    with pytest.raises(ValidationError, match="both.*identity.*resource"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_catalog_row_rejects_unavailable_evidence() -> None:
    contract = _payload()
    contract["evidence"][0].update(status="unavailable", basis=None, reason_codes=["collector_denied"])

    with pytest.raises(ValidationError, match="complete catalog rows"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_rejects_stale_evidence() -> None:
    contract = _payload()
    evaluated_at = datetime(2026, 9, 4, tzinfo=timezone.utc)
    membership = next(item for item in contract["evidence"] if item["evidence_id"] == "evidence:okta-membership:1")
    membership["freshness"] = {
        "status": "stale",
        "observed_at": (evaluated_at - timedelta(days=2)).isoformat(),
        "valid_until": (evaluated_at - timedelta(days=1)).isoformat(),
        "evaluated_at": evaluated_at.isoformat(),
        "max_age_seconds": 86_400,
    }

    with pytest.raises(ValidationError, match="fresh evidence"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_rejects_unknown_freshness() -> None:
    contract = _payload()
    membership = next(item for item in contract["evidence"] if item["evidence_id"] == "evidence:okta-membership:1")
    membership["freshness"] = None

    with pytest.raises(ValidationError, match="fresh evidence"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_rejects_evidence_observed_after_decision_time() -> None:
    contract = _payload()
    membership = next(item for item in contract["evidence"] if item["evidence_id"] == "evidence:okta-membership:1")
    membership["freshness"] = {
        "status": "fresh",
        "observed_at": (_EVALUATED_AT + timedelta(hours=1)).isoformat(),
        "valid_until": (_EVALUATED_AT + timedelta(hours=25)).isoformat(),
        "evaluated_at": _EVALUATED_AT.isoformat(),
        "max_age_seconds": _FRESHNESS_MAX_AGE_SECONDS,
    }

    with pytest.raises(ValidationError, match="future evidence"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_rejects_evidence_not_bound_to_endpoints() -> None:
    contract = _payload()
    contract["relationships"][0]["source_ref"] = "identity:service-account:github-bot"

    with pytest.raises(ValidationError, match="evidence anchor"):
        IdentityResourceJoinContract.model_validate(contract)


def test_provider_assertion_id_must_be_present_in_evidence_source_ids() -> None:
    contract = _payload()
    contract["relationships"][0]["provider_assertion_ids"] = ["unrelated-provider-assertion"]

    with pytest.raises(ValidationError, match="evidence anchors.*source_ids"):
        IdentityResourceJoinContract.model_validate(contract)


def test_semantically_duplicate_relationship_is_rejected() -> None:
    contract = _payload()
    duplicate = deepcopy(contract["relationships"][0])
    duplicate["relationship_id"] = "join:okta:alice-engineering-copy"
    contract["relationships"].append(duplicate)

    with pytest.raises(ValidationError, match="semantic relationship"):
        IdentityResourceJoinContract.model_validate(contract)


def test_relationship_id_must_match_tenant_scoped_semantics() -> None:
    contract = _payload()
    contract["relationships"][0]["relationship_id"] = "join:caller-selected"

    with pytest.raises(ValidationError, match="deterministic tenant-scoped"):
        IdentityResourceJoinContract.model_validate(contract)


def test_join_method_must_match_relationship_type() -> None:
    contract = _payload()
    contract["relationships"][0]["join_method"] = "trust_policy"

    with pytest.raises(ValidationError, match="join method"):
        IdentityResourceJoinContract.model_validate(contract)


def test_provider_must_match_its_source_family() -> None:
    contract = _payload()
    contract["identities"][0]["native_ids"][0]["provider"] = "aws"

    with pytest.raises(ValidationError, match="provider.*source family"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_provider_native_id_requires_explicit_account_scope() -> None:
    contract = _payload()
    contract["identities"][0]["native_ids"][0].pop("account", None)

    with pytest.raises(ValidationError, match="account"):
        IdentityResourceJoinContract.model_validate(contract)


def test_native_assertion_id_is_deterministic_and_scope_sensitive() -> None:
    native_id = _contract().identities[0].native_ids[0]
    same_native_id = ProviderNativeId.model_validate(native_id.model_dump(mode="json"))
    other_scope = native_id.model_copy(update={"account": "okta-org-other"})

    assert canonical_provider_native_assertion_id(native_id) == canonical_provider_native_assertion_id(same_native_id)
    assert canonical_provider_native_assertion_id(native_id) != canonical_provider_native_assertion_id(other_scope)


def test_complete_catalog_row_rejects_stale_evidence() -> None:
    contract = _payload()
    inventory = next(item for item in contract["evidence"] if item["evidence_id"] == "evidence:okta:1")
    inventory["freshness"] = {
        "status": "stale",
        "observed_at": (_EVALUATED_AT - timedelta(days=2)).isoformat(),
        "valid_until": (_EVALUATED_AT - timedelta(days=1)).isoformat(),
        "evaluated_at": _EVALUATED_AT.isoformat(),
        "max_age_seconds": _FRESHNESS_MAX_AGE_SECONDS,
    }

    with pytest.raises(ValidationError, match="catalog.*fresh"):
        IdentityResourceJoinContract.model_validate(contract)


def test_catalog_evidence_must_bind_to_exact_provider_native_id() -> None:
    contract = _payload()
    contract["identities"][0]["native_ids"][0]["value"] = "00uFabricated"
    contract["relationships"][0]["source_native_id"]["value"] = "00uFabricated"
    relationship = IdentityRelationship.model_validate(contract["relationships"][0])
    contract["relationships"][0]["relationship_id"] = canonical_identity_relationship_id(
        tenant_id=contract["tenant_id"],
        relationship=relationship,
    )

    with pytest.raises(ValidationError, match="native.*evidence source_ids"):
        IdentityResourceJoinContract.model_validate(contract)


@pytest.mark.parametrize(
    ("relationship_index", "catalog_name", "row_index"),
    [
        (0, "identities", 0),
        (1, "resources", 0),
    ],
)
def test_complete_join_rejects_unreceipted_native_id_on_partial_endpoint(
    relationship_index: int,
    catalog_name: str,
    row_index: int,
) -> None:
    contract = _payload()
    fabricated_native_id = deepcopy(contract[catalog_name][row_index]["native_ids"][0])
    fabricated_native_id["value"] = "00uFabricated"
    contract[catalog_name][row_index].update(
        native_ids=[fabricated_native_id],
        status="partial",
        reason_codes=["source_incomplete"],
    )
    contract["relationships"][relationship_index]["source_native_id"] = fabricated_native_id
    relationship = IdentityRelationship.model_validate(contract["relationships"][relationship_index])
    contract["relationships"][relationship_index]["relationship_id"] = canonical_identity_relationship_id(
        tenant_id=contract["tenant_id"],
        relationship=relationship,
    )

    with pytest.raises(ValidationError, match="endpoint native assertions.*catalog evidence source_ids"):
        IdentityResourceJoinContract.model_validate(contract)


def test_complete_join_allows_receipted_native_id_on_partial_endpoint() -> None:
    contract = _payload()
    contract["identities"][0].update(status="partial", reason_codes=["source_incomplete"])

    validated = IdentityResourceJoinContract.model_validate(contract)

    assert validated.relationships[0].asserted is True


def test_provider_native_resource_scope_includes_account() -> None:
    contract = _payload()
    account_a = deepcopy(contract["resources"][0])
    account_a["resource_id"] = "resource:azure:payments-api-org-a"
    account_a["native_ids"][0]["account"] = "subscription-a"
    account_b = deepcopy(contract["resources"][0])
    account_b["resource_id"] = "resource:azure:payments-api-org-b"
    account_b["native_ids"][0]["account"] = "subscription-b"
    contract["resources"].extend((account_a, account_b))
    _bind_native_assertion(contract, evidence_id="evidence:azure:1", native_id=account_a["native_ids"][0])
    _bind_native_assertion(contract, evidence_id="evidence:azure:1", native_id=account_b["native_ids"][0])

    validated = IdentityResourceJoinContract.model_validate(contract)

    assert len(validated.resources) == 4


def test_group_cannot_be_a_member_of_itself() -> None:
    contract = _payload()
    contract["relationships"][0].update(
        source_ref="identity:group:engineering",
        target_ref="identity:group:engineering",
    )

    with pytest.raises(ValidationError, match="member_of self-loop"):
        IdentityResourceJoinContract.model_validate(contract)


def test_checked_in_json_schema_enforces_complete_relationship_shape() -> None:
    schema = json.loads((Path("docs/schemas/v1/IdentityResourceJoinContract.json")).read_text())
    contract = _contract().model_dump(mode="json")
    contract["relationships"][0]["evidence_refs"] = []

    with pytest.raises(jsonschema.ValidationError) as exc_info:
        jsonschema.validate(contract, schema)

    assert list(exc_info.value.path)[-1] == "evidence_refs"


def test_checked_in_json_schema_enforces_partial_reason_codes() -> None:
    schema = json.loads((Path("docs/schemas/v1/IdentityResourceJoinContract.json")).read_text())
    contract = _contract().model_dump(mode="json")
    contract["relationships"][0].update(status="partial", reason_codes=[])

    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(contract, schema)


def test_checked_in_json_schema_requires_provider_scope() -> None:
    schema = json.loads((Path("docs/schemas/v1/IdentityResourceJoinContract.json")).read_text())
    contract = _contract().model_dump(mode="json")
    del contract["identities"][0]["native_ids"][0]["account"]

    with pytest.raises(jsonschema.ValidationError) as exc_info:
        jsonschema.validate(contract, schema)

    assert "account" in str(exc_info.value)


@pytest.mark.parametrize(
    ("mutator", "field"),
    [
        (lambda payload: payload["identities"][0]["native_ids"][0].update(provider="aws"), "provider"),
        (lambda payload: payload["relationships"][0].update(join_method="trust_policy"), "join_method"),
    ],
)
def test_checked_in_json_schema_enforces_local_cross_field_rules(mutator, field: str) -> None:
    schema = json.loads((Path("docs/schemas/v1/IdentityResourceJoinContract.json")).read_text())
    contract = _contract().model_dump(mode="json")
    mutator(contract)

    with pytest.raises(jsonschema.ValidationError) as exc_info:
        jsonschema.validate(contract, schema)

    assert field in str(exc_info.value)


def test_checked_in_schema_names_the_executable_validator_boundary() -> None:
    schema = json.loads((Path("docs/schemas/v1/IdentityResourceJoinContract.json")).read_text())

    assert "model_validate" in schema["$comment"]
    assert "JSON Schema alone is not sufficient" in schema["$comment"]


def test_aggregate_evidence_reference_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _payload()
    current_reference_count = sum(
        len(item["evidence_refs"]) for group in (contract["identities"], contract["resources"], contract["relationships"]) for item in group
    )
    monkeypatch.setattr(join_contract_module, "MAX_IDENTITY_JOIN_EVIDENCE_REFERENCES", current_reference_count - 1)

    with pytest.raises(ValidationError, match="aggregate evidence-reference budget"):
        IdentityResourceJoinContract.model_validate(contract)


def test_aggregate_native_identifier_budget_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    contract = _payload()
    current_native_id_count = sum(len(item["native_ids"]) for group in (contract["identities"], contract["resources"]) for item in group)
    monkeypatch.setattr(join_contract_module, "MAX_IDENTITY_JOIN_NATIVE_IDENTIFIERS", current_native_id_count - 1)

    with pytest.raises(ValidationError, match="aggregate provider-native identifier budget"):
        IdentityResourceJoinContract.model_validate(contract)
