"""At-rest encryption for cloud-connection secret material.

A cloud connection stores one secret: the AWS ``ExternalId`` (or the
provider-appropriate equivalent) that the credential broker presents when it
assumes the customer's read-only role. That value must never be persisted in
plaintext, returned in an API response, or written to a log.

Key resolution is pluggable via ``AGENT_BOM_CONNECTIONS_KEY_PROVIDER`` so a
hosted deployment can resolve the Fernet key from a managed key service instead
of a process env var. The encrypt/decrypt contract is identical across
providers; only key resolution differs. When the resolved key cannot be
obtained the module is in a clearly-degraded mode that *refuses* to encrypt —
callers raise rather than fall back to storing plaintext. The plaintext secret,
the key, and any provider error detail are never logged.

Providers (``AGENT_BOM_CONNECTIONS_KEY_PROVIDER``):

``env`` (default)
    ``AGENT_BOM_CONNECTIONS_KEY`` carries a base64 ``Fernet`` key directly. This
    is the open / self-hosted default and is unchanged from Phase A.

``aws-secrets``
    The base64 ``Fernet`` key is fetched from AWS Secrets Manager at the secret
    id/ARN named by ``AGENT_BOM_CONNECTIONS_KEY_REF`` using a read-only
    ``secretsmanager:GetSecretValue``. Nothing about the key is stored locally.

``aws-kms``
    Envelope encryption. ``AGENT_BOM_CONNECTIONS_KEY`` holds a KMS-wrapped
    (base64) data key — the ``CiphertextBlob`` an operator produces once with
    ``aws kms generate-data-key --key-id <cmk> --number-of-bytes 32`` (the wrap
    step). At load the blob is decrypted with ``kms:Decrypt`` and the recovered
    32-byte data key is encoded into a ``Fernet`` key. The plaintext data key
    never touches disk.

``vault``
    The base64 ``Fernet`` key is fetched from a HashiCorp Vault **KV v2** secret
    over a read-only ``GET {AGENT_BOM_VAULT_ADDR}/v1/{mount}/data/{path}`` with
    an ``X-Vault-Token: {AGENT_BOM_VAULT_TOKEN}`` header.
    ``AGENT_BOM_CONNECTIONS_KEY_REF`` names the location and field as
    ``mount/path#field`` (the ``#field`` suffix is optional and defaults to
    ``key``). TLS verification stays on; nothing about the key or token is
    stored locally or logged.

Planned seam: ``azure-keyvault`` and ``gcp-secret-manager`` follow the same
resolver contract (return the base64 Fernet key, fail closed on any error) and
can be added without touching the encrypt/decrypt API below.

The resolved key is cached in-process; :func:`reset_key_cache` clears it (used
by tests and by an operator-driven rotation). Any resolution failure — missing
ref, access denied, malformed material — raises :class:`ConnectionSecretError`;
the deployment fails closed and never persists plaintext.

Key rotation (MultiFernet)
--------------------------

Every provider's resolved value may be a **comma-separated list** of base64
``Fernet`` keys. When more than one key is present the module builds a
``MultiFernet``: it **encrypts with the first (primary) key and decrypts with
any** key in the list. A single key stays a plain ``Fernet`` (fully backward
compatible — existing single-key deployments are unchanged).

This is the standard zero-downtime rotation procedure:

1. **Add** a freshly generated key as the new *primary* (prepend it), keeping
   the old key in the list, e.g.
   ``AGENT_BOM_CONNECTIONS_KEY="<new>,<old>"`` (or store the comma-separated
   list in the managed provider). New writes use ``<new>``; existing ciphertext
   still decrypts under ``<old>``.
2. **Re-encrypt** (optional but recommended) existing rows in the background;
   each decrypt-then-encrypt round-trip rewraps the row under the primary key.
3. **Remove** the retired key from the list once no ciphertext depends on it,
   leaving only ``AGENT_BOM_CONNECTIONS_KEY="<new>"``.

``reset_key_cache`` must be called after changing the configured keys so the
next operation re-resolves the rotated list.
"""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from typing import Any

from agent_bom.config import resolved_vault_addr

CONNECTIONS_KEY_ENV = "AGENT_BOM_CONNECTIONS_KEY"
CONNECTIONS_KEY_PROVIDER_ENV = "AGENT_BOM_CONNECTIONS_KEY_PROVIDER"
CONNECTIONS_KEY_REF_ENV = "AGENT_BOM_CONNECTIONS_KEY_REF"
VAULT_ADDR_ENV = "AGENT_BOM_VAULT_ADDR"
VAULT_TOKEN_ENV = "AGENT_BOM_VAULT_TOKEN"

PROVIDER_ENV = "env"
PROVIDER_AWS_SECRETS = "aws-secrets"
PROVIDER_AWS_KMS = "aws-kms"
PROVIDER_VAULT = "vault"

# Default field name inside a Vault KV v2 secret when ``...#field`` is omitted.
DEFAULT_VAULT_FIELD = "key"

# In-process cache of the resolved key material. ``None`` means "not yet
# resolved"; cleared by :func:`reset_key_cache`. The value may carry a
# comma-separated list of base64 Fernet keys (MultiFernet rotation).
_RESOLVED_KEY: bytes | None = None


class ConnectionSecretError(RuntimeError):
    """Raised when a connection secret cannot be encrypted or decrypted.

    The message intentionally never embeds the plaintext secret, the key, or a
    provider's error detail — only the failure mode — so it is safe to surface
    in an error envelope or log.
    """


def _provider() -> str:
    """Return the configured key provider, normalized; defaults to ``env``."""
    return os.environ.get(CONNECTIONS_KEY_PROVIDER_ENV, PROVIDER_ENV).strip().lower() or PROVIDER_ENV


def reset_key_cache() -> None:
    """Clear the in-process resolved-key cache.

    Forces the next encrypt/decrypt to re-resolve the key through the configured
    provider. Used by tests and by operator-driven key rotation.
    """
    global _RESOLVED_KEY
    _RESOLVED_KEY = None


def connections_key_configured() -> bool:
    """Return whether an at-rest encryption key is *configured* for the provider.

    Used by the API to fail closed *before* accepting a secret. This checks that
    the configuration a provider needs is present (env key / secret ref / wrapped
    key); it does not make a network call. Actual resolution failures still fail
    closed at encrypt/decrypt time, so a denied/malformed managed key never
    results in stored plaintext.
    """
    if _RESOLVED_KEY is not None:
        return True
    provider = _provider()
    if provider == PROVIDER_ENV:
        return bool(os.environ.get(CONNECTIONS_KEY_ENV, "").strip())
    if provider == PROVIDER_AWS_SECRETS:
        return bool(os.environ.get(CONNECTIONS_KEY_REF_ENV, "").strip())
    if provider == PROVIDER_AWS_KMS:
        return bool(os.environ.get(CONNECTIONS_KEY_ENV, "").strip())
    if provider == PROVIDER_VAULT:
        return bool(
            resolved_vault_addr()
            and os.environ.get(VAULT_TOKEN_ENV, "").strip()
            and os.environ.get(CONNECTIONS_KEY_REF_ENV, "").strip()
        )
    return False


def _boto3_client(service: str, provider: str) -> Any:
    """Return a boto3 client for ``service`` or fail closed.

    boto3 is an optional (``[aws]``) dependency; its absence is a configuration
    error for the AWS-backed providers, not a reason to fall back to plaintext.
    """
    try:
        import boto3
    except ImportError as exc:
        raise ConnectionSecretError(
            f"boto3 is required for the '{provider}' connection key provider. Install with: pip install 'agent-bom[aws]'."
        ) from exc
    return boto3.client(service)


def _resolve_env() -> bytes:
    """Resolve the base64 Fernet key from ``AGENT_BOM_CONNECTIONS_KEY`` or ``*_FILE``."""
    from agent_bom.api.secret_source import resolve_secret

    raw = resolve_secret(CONNECTIONS_KEY_ENV)
    if not raw:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_ENV} (or {CONNECTIONS_KEY_ENV}_FILE) is not set; refusing to store or "
            "read a connection secret in plaintext. Provide a base64 Fernet key (or set "
            f"{CONNECTIONS_KEY_PROVIDER_ENV} to a managed key provider)."
        )
    return raw.encode("ascii")


def _resolve_aws_secrets() -> bytes:
    """Fetch the base64 Fernet key from AWS Secrets Manager (read-only)."""
    ref = os.environ.get(CONNECTIONS_KEY_REF_ENV, "").strip()
    if not ref:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_PROVIDER_ENV}={PROVIDER_AWS_SECRETS} requires {CONNECTIONS_KEY_REF_ENV} "
            "(the secret id/ARN of the base64 Fernet key); refusing to fall back to plaintext."
        )
    client = _boto3_client("secretsmanager", PROVIDER_AWS_SECRETS)
    try:
        response = client.get_secret_value(SecretId=ref)
    except Exception as exc:  # noqa: BLE001 - botocore ClientError et al.
        # Never echo the provider error (it can carry the secret ARN/account).
        raise ConnectionSecretError("Unable to resolve the connection encryption key from AWS Secrets Manager.") from exc
    raw = (response.get("SecretString") or "").strip()
    if not raw:
        raise ConnectionSecretError("AWS Secrets Manager returned an empty connection encryption key.")
    return raw.encode("ascii")


def _resolve_aws_kms() -> bytes:
    """Unwrap the KMS-wrapped data key in ``AGENT_BOM_CONNECTIONS_KEY``.

    The env var (or ``*_FILE``) holds the base64 ``CiphertextBlob`` produced by KMS
    ``GenerateDataKey``; ``kms:Decrypt`` recovers the 32-byte data key, which is
    encoded into a ``Fernet`` key.
    """
    from agent_bom.api.secret_source import resolve_secret

    wrapped = resolve_secret(CONNECTIONS_KEY_ENV)
    if not wrapped:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_PROVIDER_ENV}={PROVIDER_AWS_KMS} requires {CONNECTIONS_KEY_ENV} "
            "to hold a KMS-wrapped (base64) data key; refusing to fall back to plaintext."
        )
    try:
        ciphertext_blob = base64.b64decode(wrapped, validate=True)
    except Exception as exc:  # noqa: BLE001 - malformed base64
        raise ConnectionSecretError(f"{CONNECTIONS_KEY_ENV} is not a valid base64 KMS-wrapped data key.") from exc
    client = _boto3_client("kms", PROVIDER_AWS_KMS)
    try:
        response = client.decrypt(CiphertextBlob=ciphertext_blob)
    except Exception as exc:  # noqa: BLE001 - botocore ClientError et al.
        # Never echo the provider error (it can carry the KMS key ARN/account).
        raise ConnectionSecretError("Unable to decrypt the connection encryption key with AWS KMS.") from exc
    plaintext = response.get("Plaintext")
    if not plaintext:
        raise ConnectionSecretError("AWS KMS returned an empty data key.")
    # Encode the raw data key into a urlsafe-base64 Fernet key. A wrong-length
    # data key yields an invalid Fernet key and fails closed at construction.
    return base64.urlsafe_b64encode(bytes(plaintext))


def _parse_vault_ref(ref: str) -> tuple[str, str, str]:
    """Parse ``mount/path#field`` into ``(mount, path, field)``.

    ``#field`` is optional and defaults to :data:`DEFAULT_VAULT_FIELD`. Raises
    :class:`ConnectionSecretError` when the mount or path is missing.
    """
    location, _, field = ref.partition("#")
    field = field.strip() or DEFAULT_VAULT_FIELD
    mount, _, path = location.strip().strip("/").partition("/")
    if not mount or not path:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_REF_ENV} for the '{PROVIDER_VAULT}' provider must be "
            "'mount/path[#field]' (the KV v2 mount and secret path); refusing to fall back to plaintext."
        )
    return mount, path, field


def _resolve_vault() -> bytes:
    """Fetch the base64 Fernet key from a HashiCorp Vault KV v2 secret (read-only)."""
    addr = resolved_vault_addr().rstrip("/")
    token = os.environ.get(VAULT_TOKEN_ENV, "").strip()
    ref = os.environ.get(CONNECTIONS_KEY_REF_ENV, "").strip()
    if not addr or not token or not ref:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_PROVIDER_ENV}={PROVIDER_VAULT} requires {VAULT_ADDR_ENV}, "
            f"{VAULT_TOKEN_ENV}, and {CONNECTIONS_KEY_REF_ENV} (mount/path#field); "
            "refusing to fall back to plaintext."
        )
    mount, path, field = _parse_vault_ref(ref)
    url = f"{addr}/v1/{mount}/data/{path}"

    from agent_bom import http_client

    try:
        # Read-only GET via the shared client (TLS verification on by default).
        response = http_client.sync_get(url, headers={"X-Vault-Token": token})
    except Exception as exc:  # noqa: BLE001 - never echo the token or transport detail
        raise ConnectionSecretError("Unable to reach HashiCorp Vault to resolve the connection encryption key.") from exc
    if response is None:
        raise ConnectionSecretError("Unable to reach HashiCorp Vault to resolve the connection encryption key.")
    if response.status_code != 200:
        # Status only — never the body (it can carry the token/policy detail).
        raise ConnectionSecretError(f"HashiCorp Vault returned HTTP {response.status_code} resolving the connection encryption key.")
    try:
        body = response.json()
        value = body["data"]["data"][field]
    except Exception as exc:  # noqa: BLE001 - malformed body / missing field
        raise ConnectionSecretError(
            "HashiCorp Vault response did not contain the connection encryption key at the configured field."
        ) from exc
    raw = (value or "").strip() if isinstance(value, str) else ""
    if not raw:
        raise ConnectionSecretError("HashiCorp Vault returned an empty connection encryption key.")
    return raw.encode("ascii")


_RESOLVERS: dict[str, Callable[[], bytes]] = {
    PROVIDER_ENV: _resolve_env,
    PROVIDER_AWS_SECRETS: _resolve_aws_secrets,
    PROVIDER_AWS_KMS: _resolve_aws_kms,
    PROVIDER_VAULT: _resolve_vault,
}


def _load_key() -> bytes:
    """Resolve the base64 Fernet key through the configured provider, cached.

    Raises :class:`ConnectionSecretError` when the key is unresolvable — the
    no-plaintext-fallback guarantee — or the provider is unknown.
    """
    global _RESOLVED_KEY
    if _RESOLVED_KEY is not None:
        return _RESOLVED_KEY
    provider = _provider()
    resolver = _RESOLVERS.get(provider)
    if resolver is None:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_PROVIDER_ENV}={provider!r} is not a supported key provider; "
            f"expected one of {PROVIDER_ENV!r}, {PROVIDER_AWS_SECRETS!r}, {PROVIDER_AWS_KMS!r}, {PROVIDER_VAULT!r}."
        )
    key = resolver()
    _RESOLVED_KEY = key
    return key


def _split_keys(material: bytes) -> list[bytes]:
    """Split resolved key material into individual base64 Fernet keys.

    Supports a comma-separated list for MultiFernet rotation; surrounding
    whitespace and empty entries are ignored.
    """
    return [chunk.strip() for chunk in material.split(b",") if chunk.strip()]


def _fernet() -> Any:
    """Build a Fernet (single key) or MultiFernet (rotation list).

    A single key stays a plain ``Fernet`` for backward compatibility. With more
    than one key a ``MultiFernet`` encrypts under the first (primary) key and
    decrypts under any key in the list.
    """
    try:
        from cryptography.fernet import Fernet, MultiFernet
    except ImportError as exc:  # pragma: no cover - cryptography is a core dependency
        raise ConnectionSecretError("cryptography is required for connection secret encryption.") from exc
    keys = _split_keys(_load_key())
    if not keys:
        raise ConnectionSecretError("No connection encryption key is configured; refusing to operate on plaintext.")
    try:
        fernets = [Fernet(key) for key in keys]
        return fernets[0] if len(fernets) == 1 else MultiFernet(fernets)
    except ConnectionSecretError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed key material
        # Never echo the key or its decode error detail; only the failure mode.
        raise ConnectionSecretError("The resolved connection encryption key is not a valid Fernet key.") from exc


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a connection secret, returning a Fernet token (base64 text).

    Raises :class:`ConnectionSecretError` when no key is configured, so an
    unconfigured deployment fails closed instead of persisting plaintext.
    """
    if plaintext == "":
        raise ConnectionSecretError("Refusing to encrypt an empty connection secret.")
    fernet = _fernet()
    token = fernet.encrypt(plaintext.encode("utf-8"))
    return str(token.decode("ascii"))


def decrypt_secret(token: str) -> str:
    """Decrypt a Fernet token back to the plaintext connection secret.

    The only caller is the credential broker, immediately before it presents
    the value to the cloud provider. The result is never logged or returned to
    an API client.
    """
    if not token:
        raise ConnectionSecretError("No connection secret ciphertext to decrypt.")
    fernet = _fernet()
    try:
        plaintext = fernet.decrypt(token.encode("ascii"))
    except ConnectionSecretError:
        raise
    except Exception as exc:  # noqa: BLE001 - invalid/again-rotated token
        raise ConnectionSecretError("Connection secret ciphertext could not be decrypted with the configured key.") from exc
    return str(plaintext.decode("utf-8"))
