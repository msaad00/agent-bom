"""Credential broker for stored read-only cloud connections.

The broker is the *only* place a stored connection secret is decrypted. Given a
:class:`~agent_bom.api.connection_store.CloudConnectionRecord`, it produces a
short-lived, read-only cloud session / credential / connection that discovery
runs against — the control plane never holds long-lived customer keys beyond the
single encrypted secret per connection, which is decrypted only at broker time.

All four providers are broker-enabled:

- **AWS** — ``sts:AssumeRole(RoleArn=role_ref, ExternalId=<decrypted
  external_id>)`` returns a ``boto3.Session`` backed by temporary credentials.
- **Azure** — ``ClientSecretCredential(tenant_id, client_id=role_ref,
  client_secret=<decrypted secret>)`` (``tenant_id`` from ``auth_params``).
  The customer grants the app the read-only Reader role.
- **GCP** — ``service_account.Credentials.from_service_account_info`` built from
  the decrypted service-account key JSON, scoped to the read-only
  ``cloud-platform.read-only`` scope.
- **Snowflake** — ``snowflake.connector.connect`` using the decrypted PEM
  private key (loaded to DER via ``cryptography``) for key-pair auth, with
  ``account`` from ``role_ref`` and ``user`` / ``role`` / ``warehouse`` from
  ``auth_params``.

The decrypted secret is presented to the provider and never logged or returned.
Each broker fails closed with :class:`ConnectionBrokerError` whose message
carries only the connection id and failure mode — never the secret.

Read-only posture: the broker assumes the role / uses the identity the
connection points at; it performs no write/mutating API calls. Enforcing that
the role / identity grants only read permissions is the customer's IAM
responsibility (and is surfaced by the read-only role modules and discovery
envelope elsewhere in the product).
"""

from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

from agent_bom.api.connection_crypto import ConnectionSecretError, decrypt_secret
from agent_bom.cloud.base import CloudDiscoveryError

if TYPE_CHECKING:
    from agent_bom.api.connection_store import CloudConnectionRecord

logger = logging.getLogger(__name__)

# Default STS session duration (seconds). Short-lived by design.
_DEFAULT_SESSION_DURATION = 3600

# Read-only OAuth scope for GCP service-account credentials. The cloud-platform
# read-only scope cannot authorize any mutating API, so the brokered credential
# is structurally incapable of a write even if a caller asked for one.
_GCP_READONLY_SCOPE = "https://www.googleapis.com/auth/cloud-platform.read-only"


class ConnectionBrokerError(RuntimeError):
    """Raised when a connection cannot be brokered into a cloud session.

    Messages never embed the decrypted secret — only the failure mode — so they
    are safe to log. For anything surfaced to the operator, callers must set an
    explicit, curated ``remediation`` string (why + how to fix). The API layer
    surfaces ONLY ``remediation`` — never the free-form message — so a stray
    secret in a message can never reach the client (defense in depth).
    """

    def __init__(self, message: str, *, remediation: str | None = None) -> None:
        super().__init__(message)
        self.remediation = remediation


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
        # only the connection id and a generic cause. The control plane's OWN
        # (caller) identity performs the AssumeRole; if it has no base
        # credentials, botocore raises NoCredentialsError before any role is
        # assumed — a distinct, actionable failure from a mis-scoped role/trust.
        # Match by class name so botocore need not be imported here.
        if exc.__class__.__name__ == "NoCredentialsError":
            logger.warning(
                "AWS control plane has no base credentials to assume the role for connection %s",
                record.id,
            )
            raise ConnectionBrokerError(
                f"AWS control plane has no base credentials for connection {record.id}.",
                remediation=(
                    "Control plane has no AWS credentials to assume the role. In production the "
                    "control plane runs with an EC2 instance profile or IRSA; for local use, "
                    "configure AWS credentials for the control plane (AWS_PROFILE or the standard "
                    "environment variables). The connection's read-only role is fine — this is the "
                    "caller identity that performs sts:AssumeRole (which also needs sts:AssumeRole "
                    "permission, and for same-account roles, on the base identity)."
                ),
            ) from exc
        logger.warning("AWS AssumeRole failed for connection %s", record.id)
        raise ConnectionBrokerError(
            f"AssumeRole failed for connection {record.id}.",
            remediation=(
                "AssumeRole failed. Verify the role ARN, its trust policy, and that the "
                "ExternalId matches the one embedded in the grant script. The control plane's "
                "caller identity also needs sts:AssumeRole permission on that role."
            ),
        ) from exc
    finally:
        # Drop the plaintext reference as soon as the call returns.
        external_id = ""

    creds = assumed.get("Credentials", {})
    # The "all regions" sentinel is not a real region — leave the session's
    # region unset so the default resolves and the multi-region fan-out enumerates
    # the enabled set from these credentials.
    from agent_bom.cloud.aws_inventory import is_all_regions

    region = None if is_all_regions(record.regions) else (record.regions[0] if record.regions else None)
    return boto3.Session(
        aws_access_key_id=creds.get("AccessKeyId"),
        aws_secret_access_key=creds.get("SecretAccessKey"),
        aws_session_token=creds.get("SessionToken"),
        region_name=region,
    )


def _decrypt_or_fail(record: CloudConnectionRecord) -> str:
    """Decrypt the connection's single secret, mapping failures to a safe error.

    The returned plaintext is the secret the provider broker presents (Azure
    client secret / GCP SA-key JSON / Snowflake PEM private key). Callers must
    clear the local reference as soon as the provider call returns.
    """
    try:
        return decrypt_secret(record.external_id_encrypted)
    except ConnectionSecretError as exc:
        # Surface the failure mode, never the ciphertext or key detail.
        raise ConnectionBrokerError(f"Unable to access connection secret for {record.id}: {exc}") from exc


def _broker_azure(record: CloudConnectionRecord) -> Any:
    """Build a read-only Azure ``ClientSecretCredential`` for the connection.

    ``role_ref`` is the app/service-principal client id, the decrypted secret is
    the client secret, and ``auth_params`` carries ``tenant_id`` (required) and
    ``subscription_id`` (used by the scan route). The customer grants the app the
    read-only Reader role; the broker never makes a write call.
    """
    try:
        from azure.identity import ClientSecretCredential
    except ImportError as exc:
        raise CloudDiscoveryError(
            "azure-identity is required to broker Azure connections. Install with: pip install 'agent-bom[azure]'"
        ) from exc

    tenant_id = str(record.auth_params.get("tenant_id") or "").strip()
    if not tenant_id:
        raise ConnectionBrokerError(f"Azure connection {record.id} is missing required auth_params.tenant_id.")
    client_id = (record.role_ref or "").strip()
    if not client_id:
        raise ConnectionBrokerError(f"Azure connection {record.id} is missing the client id (role_ref).")

    client_secret = _decrypt_or_fail(record)
    try:
        return ClientSecretCredential(tenant_id=tenant_id, client_id=client_id, client_secret=client_secret)
    except Exception as exc:  # noqa: BLE001 - azure-identity construction error
        logger.warning("Azure credential construction failed for connection %s", record.id)
        raise ConnectionBrokerError(f"Azure credential construction failed for connection {record.id}.") from exc
    finally:
        # Drop the plaintext reference as soon as the credential is built.
        client_secret = ""


def _broker_gcp(record: CloudConnectionRecord) -> Any:
    """Build read-only GCP service-account credentials from the stored key JSON.

    ``role_ref`` is the service-account email, the decrypted secret is the
    service-account key JSON, and ``auth_params`` carries ``project_id`` (used by
    the scan route). Credentials are scoped to the read-only cloud-platform scope
    so they cannot authorize any mutating API.
    """
    try:
        from google.oauth2 import service_account
    except ImportError as exc:
        raise CloudDiscoveryError("google-auth is required to broker GCP connections. Install with: pip install 'agent-bom[gcp]'") from exc

    key_json = _decrypt_or_fail(record)
    try:
        key_info = json.loads(key_json)
    except (ValueError, TypeError) as exc:
        # Never echo the key material — only the failure mode.
        key_json = ""
        raise ConnectionBrokerError(f"GCP connection {record.id} service-account key is not valid JSON.") from exc
    try:
        return service_account.Credentials.from_service_account_info(key_info, scopes=[_GCP_READONLY_SCOPE])
    except Exception as exc:  # noqa: BLE001 - google-auth construction error
        logger.warning("GCP credential construction failed for connection %s", record.id)
        raise ConnectionBrokerError(f"GCP credential construction failed for connection {record.id}.") from exc
    finally:
        # Drop the plaintext key material and parsed copy as soon as we are done.
        key_json = ""
        key_info = {}


def connect_snowflake_keypair(
    *,
    account: str,
    user: str,
    private_key_pem: str,
    role: str = "",
    warehouse: str = "",
    database: str = "",
    schema: str = "",
) -> Any:
    """Open a ``snowflake.connector`` connection via key-pair auth (PEM → DER).

    This is the single home for the key-pair connect path so every caller — the
    read-only discovery broker and the findings-export writer — presents the PEM
    the same way (loaded to PKCS8 DER via ``cryptography`` as ``private_key``, no
    password). ``account`` and ``user`` are required; ``role`` / ``warehouse`` /
    ``database`` / ``schema`` scope the session when supplied. The PEM is never
    logged and its DER buffer is cleared after the connect attempt.
    """
    try:
        import snowflake.connector
    except ImportError as exc:
        raise CloudDiscoveryError(
            "snowflake-connector-python is required for Snowflake connections. Install with: pip install 'agent-bom[snowflake]'"
        ) from exc
    try:
        from cryptography.hazmat.primitives import serialization
    except ImportError as exc:  # pragma: no cover - cryptography is a core dependency
        raise CloudDiscoveryError("cryptography is required for Snowflake connections.") from exc

    if not account:
        raise ConnectionBrokerError("Snowflake connection is missing the account.")
    if not user:
        raise ConnectionBrokerError("Snowflake connection is missing the user.")

    try:
        private_key = serialization.load_pem_private_key(private_key_pem.encode("utf-8"), password=None)
        der = private_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    except Exception as exc:  # noqa: BLE001 - malformed PEM / unsupported key
        # Never echo the key material — only the failure mode.
        raise ConnectionBrokerError("Snowflake private key could not be loaded.") from exc

    conn_kwargs: dict[str, Any] = {"account": account, "user": user, "private_key": der}
    if role:
        conn_kwargs["role"] = role
    if warehouse:
        conn_kwargs["warehouse"] = warehouse
    if database:
        conn_kwargs["database"] = database
    if schema:
        conn_kwargs["schema"] = schema
    try:
        return snowflake.connector.connect(**conn_kwargs)
    finally:
        der = b""


# Bounded connect timeout (seconds) for a brokered database session so a wedged
# host fails closed rather than hanging the scan.
_DB_CONNECT_TIMEOUT = 10

# Providers brokered as a read-only PostgreSQL-wire connection (RDS/Aurora/plain
# Postgres). Snowflake keeps its dedicated key-pair broker above.
_DATABASE_PROVIDERS = frozenset({"database", "postgres", "postgresql", "rds"})


def _broker_database(record: CloudConnectionRecord) -> Any:
    """Open a read-only PostgreSQL-wire connection for a stored DB connection.

    The single encrypted secret is the libpq connection string / URL (it carries
    the password); ``role_ref`` is a non-secret display DSN. The session is opened
    ``default_transaction_read_only=on`` so any write the scan path could issue
    fails closed at the server — the DSPM content scan only ever runs bounded
    ``SELECT``s. The decrypted DSN is never logged and its local reference is
    cleared as soon as the connect returns.
    """
    try:
        import psycopg
    except ImportError as exc:
        raise CloudDiscoveryError(
            "psycopg is required to broker database connections. Install with: pip install 'agent-bom[postgres]'"
        ) from exc

    dsn = _decrypt_or_fail(record)
    try:
        return psycopg.connect(
            dsn,
            autocommit=True,
            connect_timeout=_DB_CONNECT_TIMEOUT,
            options="-c default_transaction_read_only=on",
        )
    except Exception as exc:  # noqa: BLE001 - libpq connect error (may carry host detail)
        logger.warning("Database connection failed for connection %s", record.id)
        raise ConnectionBrokerError(
            f"Database connection failed for connection {record.id}.",
            remediation=(
                "The read-only database connection could not be opened. Verify the stored "
                "connection string (host, port, database, user), that the user is granted "
                "read-only SELECT on the scoped schemas, and that the host is reachable."
            ),
        ) from exc
    finally:
        # Drop the plaintext DSN reference as soon as the connect returns.
        dsn = ""  # noqa: F841


def _broker_snowflake(record: CloudConnectionRecord) -> Any:
    """Open a read-only Snowflake connection via key-pair auth for the connection.

    ``role_ref`` is the ``account`` (or ``account/user``), the decrypted secret is
    the PEM private key, and ``auth_params`` carries ``user`` / ``role`` /
    ``warehouse``. Delegates the actual connect to :func:`connect_snowflake_keypair`
    so the key-pair path is shared with the findings-export writer.
    """
    ref = (record.role_ref or "").strip()
    if not ref:
        raise ConnectionBrokerError(f"Snowflake connection {record.id} is missing the account (role_ref).")
    # Support either "account" or "account/user"; auth_params.user takes priority.
    account, _, ref_user = ref.partition("/")
    account = account.strip()
    user = str(record.auth_params.get("user") or ref_user or "").strip()
    role = str(record.auth_params.get("role") or "").strip()
    warehouse = str(record.auth_params.get("warehouse") or "").strip()
    if not account:
        raise ConnectionBrokerError(f"Snowflake connection {record.id} is missing the account (role_ref).")
    if not user:
        raise ConnectionBrokerError(f"Snowflake connection {record.id} is missing required auth_params.user.")

    pem = _decrypt_or_fail(record)
    try:
        return connect_snowflake_keypair(
            account=account,
            user=user,
            private_key_pem=pem,
            role=role,
            warehouse=warehouse,
        )
    except ConnectionBrokerError as exc:
        # Re-scope generic connect/key errors to the specific connection id.
        raise ConnectionBrokerError(f"Snowflake connection {record.id}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001 - connector error (may carry account detail)
        logger.warning("Snowflake connection failed for connection %s", record.id)
        raise ConnectionBrokerError(f"Snowflake connection failed for connection {record.id}.") from exc
    finally:
        pem = ""


def broker_session(
    record: CloudConnectionRecord,
    *,
    session_name: str = "agent-bom-readonly-scan",
    duration_seconds: int = _DEFAULT_SESSION_DURATION,
) -> Any:
    """Return a read-only cloud session / credential / connection for a connection.

    Dispatches by provider and returns the provider-appropriate object:

    - ``aws``       → ``boto3.Session`` (temporary AssumeRole credentials)
    - ``azure``     → ``azure.identity.ClientSecretCredential``
    - ``gcp``       → ``google.oauth2.service_account.Credentials`` (read-only)
    - ``snowflake`` → a live ``snowflake.connector`` connection (caller closes it)
    - ``database`` / ``postgres`` / ``rds`` → a live read-only ``psycopg``
      connection (``default_transaction_read_only=on``; caller closes it)

    Raises:
        ConnectionBrokerError: brokering failed (secret access or provider auth).
        CloudDiscoveryError: the provider SDK extra is not installed.
        ValueError: provider is unknown.
    """
    provider = (record.provider or "").strip().lower()
    if provider == "aws":
        return _broker_aws(record, session_name=session_name, duration_seconds=duration_seconds)
    if provider == "azure":
        return _broker_azure(record)
    if provider == "gcp":
        return _broker_gcp(record)
    if provider == "snowflake":
        return _broker_snowflake(record)
    if provider in _DATABASE_PROVIDERS:
        return _broker_database(record)
    raise ValueError(f"Unknown connection provider '{record.provider}'.")
