"""Live validation for credential reference records (metadata-only registry)."""

from __future__ import annotations

import re

from agent_bom.api.models import CredentialRefRecord, CredentialRefStatus
from agent_bom.cloud.auth_probe import verify_credentials

_AWS_ROLE_ARN = re.compile(r"^arn:aws:iam::\d{12}:role/[\w+=,.@-]+$")
_CLOUD_PROVIDERS = frozenset({"aws", "azure", "gcp", "snowflake"})


def validate_credential_ref(credential: CredentialRefRecord) -> tuple[CredentialRefStatus, str]:
    """Probe provider reachability and validate ``external_ref`` shape.

    Credential refs never store secret material — cloud probes use the scanner
    host's default credential chain to prove provider reachability. IAM role
    ARNs are format-checked; AssumeRole against the referenced role requires a
    brokered cloud connection with stored trust material.
    """
    if not credential.enabled:
        return CredentialRefStatus.DISABLED, "Credential reference is disabled."

    external_ref = (credential.external_ref or "").strip()
    if not external_ref:
        return CredentialRefStatus.DEGRADED, "external_ref is required for validation."

    provider = (credential.provider or "").strip().lower()
    mode = (credential.mode or "").strip().lower()

    if provider == "aws" and mode == "role_arn" and not _AWS_ROLE_ARN.match(external_ref):
        return CredentialRefStatus.DEGRADED, "external_ref is not a valid IAM role ARN."

    if provider in _CLOUD_PROVIDERS:
        ok, detail = verify_credentials(provider)
        if not ok:
            return CredentialRefStatus.DEGRADED, f"{provider} credential probe failed: {detail}"
        if provider == "aws" and mode == "role_arn":
            return (
                CredentialRefStatus.HEALTHY,
                f"AWS identity probe succeeded ({detail}); referenced role ARN format is valid.",
            )
        return CredentialRefStatus.HEALTHY, f"{provider} identity probe succeeded ({detail})."

    if len(external_ref) < 3:
        return CredentialRefStatus.DEGRADED, "external_ref is too short to be valid."

    return (
        CredentialRefStatus.CONFIGURED,
        "Reference metadata recorded; no live provider probe is defined for this provider.",
    )
