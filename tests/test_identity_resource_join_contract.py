"""Canonical cross-provider identity/resource join contract."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from agent_bom.evidence.semantics import (
    CompletenessEntry,
    EvidenceBasis,
    EvidenceCompletenessLedger,
    EvidenceProvenance,
    EvidenceStage,
    EvidenceStatus,
)
from agent_bom.identity.join_contract import (
    CanonicalIdentityEntity,
    CanonicalIdentityType,
    CanonicalResourceReference,
    IdentityRelationship,
    IdentityRelationshipType,
    IdentityResourceJoinContract,
    IdentitySourceKind,
    ProviderNativeId,
)


def _evidence(
    evidence_id: str,
    source: str,
    *,
    basis: EvidenceBasis = EvidenceBasis.OBSERVED,
    status: EvidenceStatus = EvidenceStatus.COMPLETE,
) -> EvidenceProvenance:
    return EvidenceProvenance(
        evidence_id=evidence_id,
        basis=basis,
        status=status,
        source=source,
        reason_codes=() if status is EvidenceStatus.COMPLETE else ("source_incomplete",),
    )


def _native(source: IdentitySourceKind, provider: str, id_type: str, value: str) -> ProviderNativeId:
    return ProviderNativeId(source=source, provider=provider, id_type=id_type, value=value)


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


def _contract() -> IdentityResourceJoinContract:
    evidence = (
        _evidence("evidence:okta:1", "okta-scim"),
        _evidence("evidence:aws:1", "aws-iam"),
        _evidence("evidence:azure:1", "azure-graph"),
        _evidence("evidence:gcp:1", "gcp-iam"),
        _evidence("evidence:saas:1", "github-saas"),
        _evidence("evidence:okta-membership:1", "okta-membership"),
        _evidence("evidence:azure-binding:1", "azure-workload-binding"),
        _evidence("evidence:aws-trust:1", "aws-trust-policy"),
        _evidence("evidence:asset-owner:1", "asset-owner-catalog"),
    )
    identities = (
        _identity(
            "identity:person:alice",
            CanonicalIdentityType.PERSON,
            _native(IdentitySourceKind.OKTA, "okta", "user_id", "00uABCDef123"),
            "evidence:okta:1",
            display_name="Alice Example",
        ),
        _identity(
            "identity:group:engineering",
            CanonicalIdentityType.GROUP,
            _native(IdentitySourceKind.OKTA, "okta", "group_id", "00gEng-Prod"),
            "evidence:okta:1",
        ),
        _identity(
            "identity:role:deploy",
            CanonicalIdentityType.ROLE,
            _native(
                IdentitySourceKind.AWS,
                "aws",
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
                "email",
                "Scanner@project-1.iam.gserviceaccount.com",
            ),
            "evidence:gcp:1",
        ),
        _identity(
            "identity:service-account:github-bot",
            CanonicalIdentityType.SERVICE_ACCOUNT,
            _native(IdentitySourceKind.SAAS, "github", "app_id", "Iv1.AbcDEF-123"),
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
                    "arn",
                    "arn:aws:s3:::Artifact-Bucket-Prod",
                ),
            ),
            evidence_refs=("evidence:aws:1",),
        ),
    )
    relationships = (
        IdentityRelationship(
            relationship_id="join:okta:alice-engineering",
            relationship_type=IdentityRelationshipType.MEMBER_OF,
            source_ref="identity:person:alice",
            target_ref="identity:group:engineering",
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:okta-membership:1",),
        ),
        IdentityRelationship(
            relationship_id="join:azure:payments-runs-as",
            relationship_type=IdentityRelationshipType.RUNS_AS,
            source_ref="resource:azure:payments-api",
            target_ref="identity:workload:payments",
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:azure-binding:1",),
        ),
        IdentityRelationship(
            relationship_id="join:aws:deploy-trust",
            relationship_type=IdentityRelationshipType.TRUSTS,
            source_ref="identity:role:deploy",
            target_ref="identity:service-account:gcp-scanner",
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:aws-trust:1",),
        ),
        IdentityRelationship(
            relationship_id="join:saas:github-owns-bucket",
            relationship_type=IdentityRelationshipType.OWNS,
            source_ref="identity:service-account:github-bot",
            target_ref="resource:aws:artifact-bucket",
            status=EvidenceStatus.COMPLETE,
            evidence_refs=("evidence:asset-owner:1",),
        ),
    )
    return IdentityResourceJoinContract(
        tenant_id="tenant-acme",
        identities=identities,
        resources=resources,
        relationships=relationships,
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
