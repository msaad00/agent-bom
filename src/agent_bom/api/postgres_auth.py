"""Pluggable short-lived auth-token providers for passwordless Postgres.

Default deployments authenticate with a static password (Docker secret file or
env), which :mod:`agent_bom.api.postgres_common` keeps out of the DSN and hands
to the pool via connection kwargs. Setting ``AGENT_BOM_POSTGRES_AUTH_MODE=iam``
switches to a true no-passwords mode: the pool fetches a short-lived auth token
from a provider for each new connection instead of a stored password.

The only bundled provider is AWS RDS IAM authentication
(``rds.generate_db_auth_token``), selected by
``AGENT_BOM_POSTGRES_IAM_PROVIDER=aws-rds`` (the default when auth mode is
``iam``). boto3 is an optional (``[aws]``) dependency imported lazily; its
absence is a clear configuration error, never a silent fallback to a password.

This whole path is opt-in — with ``AGENT_BOM_POSTGRES_AUTH_MODE`` unset the
existing file/password path is used unchanged.
"""

from __future__ import annotations

import os
from typing import Protocol

POSTGRES_AUTH_MODE_ENV = "AGENT_BOM_POSTGRES_AUTH_MODE"
POSTGRES_IAM_PROVIDER_ENV = "AGENT_BOM_POSTGRES_IAM_PROVIDER"
POSTGRES_IAM_REGION_ENV = "AGENT_BOM_POSTGRES_IAM_REGION"

AUTH_MODE_PASSWORD = "password"
AUTH_MODE_IAM = "iam"

IAM_PROVIDER_AWS_RDS = "aws-rds"


class PostgresAuthError(RuntimeError):
    """Raised when a short-lived Postgres auth token cannot be issued.

    The message never embeds the token or a provider's error detail — only the
    failure mode — so it is safe to surface in a log or startup error.
    """


class PostgresAuthTokenProvider(Protocol):
    """Issues a short-lived auth token used in place of a static DB password."""

    def get_auth_token(self, *, host: str, port: int, username: str) -> str:
        """Return a short-lived auth token scoped to ``host``/``port``/``username``."""
        ...


class RdsIamAuthTokenProvider:
    """AWS RDS IAM auth-token provider (``rds.generate_db_auth_token``).

    Produces a signed, short-lived (15-minute) token scoped to the target
    host/port/user. boto3 is imported lazily so the default password path never
    requires the ``[aws]`` extra.
    """

    def __init__(self, *, region: str | None = None) -> None:
        self._region = (region or os.environ.get(POSTGRES_IAM_REGION_ENV, "").strip()) or None

    def get_auth_token(self, *, host: str, port: int, username: str) -> str:
        try:
            import boto3
        except ImportError as exc:
            raise PostgresAuthError(
                f"boto3 is required for {POSTGRES_AUTH_MODE_ENV}={AUTH_MODE_IAM} "
                f"({POSTGRES_IAM_PROVIDER_ENV}={IAM_PROVIDER_AWS_RDS}). "
                "Install with: pip install 'agent-bom[aws]'."
            ) from exc
        client = boto3.client("rds", region_name=self._region)
        try:
            token = client.generate_db_auth_token(
                DBHostname=host,
                Port=port,
                DBUsername=username,
                Region=self._region,
            )
        except Exception as exc:  # noqa: BLE001 - botocore ClientError et al.
            # Never echo the provider error (it can carry account/ARN detail).
            raise PostgresAuthError("Unable to generate an AWS RDS IAM auth token for Postgres.") from exc
        if not token:
            raise PostgresAuthError("AWS RDS returned an empty IAM auth token.")
        return str(token)


def postgres_auth_mode() -> str:
    """Return the configured Postgres auth mode; defaults to ``password``."""
    return (os.environ.get(POSTGRES_AUTH_MODE_ENV, "").strip().lower() or AUTH_MODE_PASSWORD)


def resolve_postgres_auth_token_provider() -> PostgresAuthTokenProvider:
    """Return the auth-token provider for the configured IAM provider.

    Defaults to the AWS RDS IAM provider. An unknown provider fails closed
    rather than falling back to a password.
    """
    provider = os.environ.get(POSTGRES_IAM_PROVIDER_ENV, "").strip().lower() or IAM_PROVIDER_AWS_RDS
    if provider == IAM_PROVIDER_AWS_RDS:
        return RdsIamAuthTokenProvider()
    raise PostgresAuthError(
        f"{POSTGRES_IAM_PROVIDER_ENV}={provider!r} is not a supported Postgres IAM token provider; "
        f"expected {IAM_PROVIDER_AWS_RDS!r}."
    )
