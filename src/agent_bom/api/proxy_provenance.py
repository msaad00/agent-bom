"""Conservative submission metadata for runtime activity storage.

This contract does not authenticate a producer. Only server ingestion code may
construct and attach it from verified request context; incoming dictionaries
are not trusted instances. Legacy callers remain unknown until integrated.
"""

import hashlib
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints, field_validator

from agent_bom.security import sanitize_text

_Identifier = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, max_length=200)]
ProducerAssurance = Literal["unknown", "caller_asserted"]


class GatewaySubmissionProvenance(BaseModel):
    """Separate the submitting collector from its reported runtime origins.

    No credential material is accepted. Submitter identity and authentication
    method describe the first accepted submission, without storing a credential ID.
    A future authenticated-producer contract requires a separate trust boundary.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")

    schema_version: Literal["gateway.submission.provenance.v1"] = "gateway.submission.provenance.v1"
    producer_assurance: ProducerAssurance = "unknown"
    submission_source_id: _Identifier
    submission_session_id: _Identifier
    reported_source_id: _Identifier = ""
    reported_session_id: _Identifier = ""
    submitter_principal_id: _Identifier = ""
    authentication_method: Literal["unknown", "api_key", "oidc", "browser_session", "proxy_header", "saml", "in_process"] = "unknown"

    @field_validator("submission_source_id", "submission_session_id", "reported_source_id", "reported_session_id")
    @classmethod
    def redact_origin(cls, value: str) -> str:
        return sanitize_text(value, max_len=200)

    @field_validator("submitter_principal_id")
    @classmethod
    def protect_principal(cls, value: str) -> str:
        if sanitize_text(value, max_len=200) != value:
            # A pseudonym of the already verified principal, never of a raw
            # credential or a key ID. Keep distinct sensitive subjects distinct.
            return "principal-sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()
        return value


def canonicalize_proxy_submission(
    payload: dict[str, object],
    *,
    source_id: str,
    session_id: str,
    request_state: object,
) -> tuple[dict[str, object], GatewaySubmissionProvenance]:
    """Bind submission metadata from admitted request state, never body claims.

    A collector may report several runtime origins. Those remain assertions;
    they do not replace the collector/session identity used by the ledger.
    """
    method = str(getattr(request_state, "auth_method", "") or "unknown")
    allowed_methods = {"api_key", "oidc", "browser_session", "proxy_header", "saml"}
    if method not in allowed_methods:
        method = "unknown"
    principal = str(getattr(request_state, "principal_id", "") or "")
    if not principal and method in {"oidc", "browser_session", "proxy_header", "saml"}:
        principal = str(getattr(request_state, "api_key_name", "") or "")
    provenance = GatewaySubmissionProvenance.model_validate(
        {
            "producer_assurance": "caller_asserted",
            "submission_source_id": source_id,
            "submission_session_id": session_id,
            "reported_source_id": str(payload.get("source_id") or ""),
            "reported_session_id": str(payload.get("session_id") or ""),
            "submitter_principal_id": principal,
            "authentication_method": method,
        }
    )
    enriched = dict(payload)
    for key in ("record_schema_version", "ingest_ordinal", "event_digest"):
        enriched.pop(key, None)
    enriched.update(
        source_id=provenance.submission_source_id,
        session_id=provenance.submission_session_id,
        producer_assurance="caller_asserted",
        submission_provenance=provenance.model_dump(),
        gateway_activity_durable=False,
    )
    return enriched, provenance


def projected_producer_assurance(payload: dict) -> ProducerAssurance:
    """Read validated server projection metadata, never a flat assurance claim.

    This is a consumer of admitted/stored records, not an authentication helper
    for incoming request bodies. Malformed or historical metadata stays unknown.
    """
    from pydantic import ValidationError

    if payload.get("record_schema_version") not in (None, "gateway.activity.record.v2"):
        return "unknown"
    metadata = payload.get("submission_provenance")
    if not isinstance(metadata, dict | GatewaySubmissionProvenance):
        return "unknown"
    try:
        provenance = GatewaySubmissionProvenance.model_validate(metadata)
    except ValidationError:
        return "unknown"
    if (provenance.submission_source_id, provenance.submission_session_id) != (payload.get("source_id"), payload.get("session_id")):
        return "unknown"
    return provenance.producer_assurance


def producer_assurance_rollup(counts: dict[str, int]) -> ProducerAssurance:
    """Mixed or empty evidence cannot be upgraded to caller-asserted."""
    return "caller_asserted" if counts.get("caller_asserted", 0) > 0 and counts.get("unknown", 0) == 0 else "unknown"


def producer_assurance_counts(payloads: list[dict]) -> dict[str, int]:
    counts = {"unknown": 0, "caller_asserted": 0}
    for payload in payloads:
        counts[projected_producer_assurance(payload)] += 1
    return counts
