"""Credential broker for stored read-only cloud connections.

The broker is the *only* place a stored connection secret is decrypted. Given a
:class:`~agent_bom.api.connection_store.CloudConnectionRecord`, it produces a
short-lived, keyless cloud session by assuming the customer's read-only role
from the control-plane identity — the control plane never holds long-lived
customer keys.

AWS is implemented in Phase A: ``sts:AssumeRole(RoleArn=role_ref,
ExternalId=<decrypted external_id>)`` returns a ``boto3.Session`` backed by the
temporary credentials. The decrypted ``ExternalId`` is presented to STS and
never logged or returned. Azure / GCP / Snowflake are recognized providers that
raise a clear "planned" error until their broker lands.

Read-only posture: the broker assumes the role the connection points at; it
performs no write/mutating API calls. Enforcing that the *role* grants only
read permissions is the customer's IAM responsibility (and is surfaced by the
read-only role modules and discovery envelope elsewhere in the product).
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_crypto import ConnectionSecretError, decrypt_secret
from agent_bom.cloud.base import CloudDiscoveryError

if TYPE_CHECKING:
    from agent_bom.api.connection_store import CloudConnectionRecord

logger = logging.getLogger(__name__)

# Default STS session duration (seconds). Short-lived by design.
_DEFAULT_SESSION_DURATION = 3600
# Providers whose broker is planned but not yet implemented.
_PLANNED_PROVIDERS = ("azure", "gcp", "snowflake")


class ConnectionBrokerError(RuntimeError):
    """Raised when a connection cannot be brokered into a cloud session.

    Messages never embed the decrypted secret — only the failure mode — so they
    are safe to surface in an error envelope or log.
    """


def _broker_aws(record: CloudConnectionRecord, *, session_name: str, duration_seconds: int) -> Any:
    """Assume the connection's read-only AWS role and return a boto3 session.

    Decrypts the stored ``ExternalId`` solely to present it to ``sts:AssumeRole``;
    the value is never logged. The returned session is backed by the temporary
    credentials STS issues — no long-lived key leaves the control plane.
    """
    try:
        import boto3
    except ImportError as exc:
        raise CloudDiscoveryError("boto3 is required to broker AWS connections. Install with: pip install 'agent-bom[aws]'") from exc

    try:
        external_id = decrypt_secret(record.external_id_encrypted)
    except ConnectionSecretError as exc:
        # Surface the failure mode, never the ciphertext or key detail.
        raise ConnectionBrokerError(f"Unable to access connection secret for {record.id}: {exc}") from exc

    sts = boto3.client("sts")
    try:
        assumed = sts.assume_role(
            RoleArn=record.role_ref,
            RoleSessionName=session_name,
            ExternalId=external_id,
            DurationSeconds=duration_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - botocore ClientError et al.
        # Do not echo the exception text (it can carry the ARN/role detail); log
        # only the connection id and a generic cause.
        logger.warning("AWS AssumeRole failed for connection %s", record.id)
        raise ConnectionBrokerError(f"AssumeRole failed for connection {record.id}.") from exc
    finally:
        # Drop the plaintext reference as soon as the call returns.
        external_id = ""

    creds = assumed.get("Credentials", {})
    region = record.regions[0] if record.regions else None
    return boto3.Session(
        aws_access_key_id=creds.get("AccessKeyId"),
        aws_secret_access_key=creds.get("SecretAccessKey"),
        aws_session_token=creds.get("SessionToken"),
        region_name=region,
    )


def broker_session(
    record: CloudConnectionRecord,
    *,
    session_name: str = "agent-bom-readonly-scan",
    duration_seconds: int = _DEFAULT_SESSION_DURATION,
) -> Any:
    """Return a read-only cloud session for a stored connection.

    AWS is brokered via ``sts:AssumeRole`` with the connection's decrypted
    ``ExternalId``. Azure / GCP / Snowflake are recognized but raise
    :class:`NotImplementedError` until their broker ships (Phase B+).

    Raises:
        ConnectionBrokerError: AWS brokering failed (secret access or AssumeRole).
        NotImplementedError: provider is recognized but not yet broker-enabled.
        ValueError: provider is unknown.
    """
    provider = (record.provider or "").strip().lower()
    if provider == "aws":
        return _broker_aws(record, session_name=session_name, duration_seconds=duration_seconds)
    if provider in _PLANNED_PROVIDERS:
        raise NotImplementedError(
            f"Connection brokering for provider '{provider}' is planned but not yet implemented (Phase B+). "
            "AWS read-only AssumeRole is supported today."
        )
    raise ValueError(f"Unknown connection provider '{record.provider}'.")
