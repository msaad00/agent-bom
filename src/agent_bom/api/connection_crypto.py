"""At-rest encryption for cloud-connection secret material.

A cloud connection stores one secret: the AWS ``ExternalId`` (or the
provider-appropriate equivalent) that the credential broker presents when it
assumes the customer's read-only role. That value must never be persisted in
plaintext, returned in an API response, or written to a log.

Key resolution is environment-only: ``AGENT_BOM_CONNECTIONS_KEY`` carries a
base64 ``Fernet`` key. When it is unset the module is in a clearly-degraded
mode that *refuses* to encrypt — callers raise rather than fall back to storing
plaintext. The plaintext secret and the key itself are never logged.

Production extension seam: ``AGENT_BOM_CONNECTIONS_KEY`` is the open default. A
hosted/enterprise deployment should resolve the key (or wrap the ciphertext)
through a KMS / secrets-manager handle instead of a process env var; replace
:func:`_load_key` with a provider that fetches the data key from KMS, AWS
Secrets Manager, Azure Key Vault, or GCP Secret Manager. The encrypt/decrypt
contract below is unchanged by that swap.
"""

from __future__ import annotations

import os
from typing import Any

CONNECTIONS_KEY_ENV = "AGENT_BOM_CONNECTIONS_KEY"


class ConnectionSecretError(RuntimeError):
    """Raised when a connection secret cannot be encrypted or decrypted.

    The message intentionally never embeds the plaintext secret or the key —
    only the failure mode — so it is safe to surface in an error envelope or log.
    """


def connections_key_configured() -> bool:
    """Return whether an at-rest encryption key is available.

    Used by the API to fail closed *before* accepting a secret when the store
    would otherwise be unable to encrypt it.
    """
    return bool(os.environ.get(CONNECTIONS_KEY_ENV, "").strip())


def _load_key() -> bytes:
    """Resolve the Fernet key from the environment.

    Raises :class:`ConnectionSecretError` when the key is missing — the
    no-plaintext-fallback guarantee — or malformed.
    """
    raw = os.environ.get(CONNECTIONS_KEY_ENV, "").strip()
    if not raw:
        raise ConnectionSecretError(
            f"{CONNECTIONS_KEY_ENV} is not set; refusing to store or read a connection secret in plaintext. "
            "Provide a base64 Fernet key (or wire a KMS/secrets-manager key provider)."
        )
    return raw.encode("ascii")


def _fernet() -> Any:
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:  # pragma: no cover - cryptography is a core dependency
        raise ConnectionSecretError("cryptography is required for connection secret encryption.") from exc
    try:
        return Fernet(_load_key())
    except ConnectionSecretError:
        raise
    except Exception as exc:  # noqa: BLE001 - malformed key material
        # Never echo the key or its decode error detail; only the failure mode.
        raise ConnectionSecretError(f"{CONNECTIONS_KEY_ENV} is not a valid base64 Fernet key.") from exc


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
