"""Conservative submission metadata for runtime activity storage.

This contract does not authenticate a producer. Only server ingestion code may
construct and attach it from verified request context; incoming dictionaries
are not trusted instances. Legacy callers remain unknown until integrated.
"""

from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, StringConstraints

_Identifier = Annotated[str, StringConstraints(strict=True, strip_whitespace=True, max_length=200)]
ProducerAssurance = Literal["unknown", "caller_asserted"]


class GatewaySubmissionProvenance(BaseModel):
    """Separate the submitting collector from its reported runtime origins.

    No credential material is accepted. Submitter identity and authentication
    method describe the first accepted submission, without storing a credential ID.
    A future authenticated-producer contract requires a separate trust boundary.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["gateway.submission.provenance.v1"] = "gateway.submission.provenance.v1"
    producer_assurance: ProducerAssurance = "unknown"
    submission_source_id: _Identifier
    submission_session_id: _Identifier
    reported_source_id: _Identifier = ""
    reported_session_id: _Identifier = ""
    submitter_principal_id: _Identifier = ""
    authentication_method: Literal["unknown", "api_key", "oidc", "browser_session", "proxy_header", "saml", "in_process"] = "unknown"
