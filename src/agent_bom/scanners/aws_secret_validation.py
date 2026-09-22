"""Explicit, bounded, read-only liveness check for a discovered AWS access key.

Calls ``sts:GetCallerIdentity`` with the discovered access key id and secret
access key — the standard, safe, read-only way to check whether an AWS
credential pair currently authenticates. The call requires no IAM permission
beyond the key's own baseline, makes no changes to the target account, and
this module never reads, stores, or logs any field of the STS response
(account id, ARN, user id) or the credential values themselves.

Never persist a credential. A verdict describes authentication at check
time, not whether the key is safe to retain in source. Any transport,
throttling, or unexpected provider error fails open to ``unknown`` — this
check never fails the scan it runs inside.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal

ValidationStatus = Literal["valid", "invalid", "unknown"]

# Bounded per scan, same budget as the generic (GitHub/Stripe) validator —
# enrichment must stay cheap relative to the scan it rides along with.
_MAX_CHECKS = 20
_CONNECT_TIMEOUT_SECONDS = 5.0
_READ_TIMEOUT_SECONDS = 5.0
# GetCallerIdentity authenticates the credential regardless of which regions
# are enabled on the target account; a fixed classic-partition region keeps
# this check from depending on any region the discovered key happens to use.
_STS_REGION = "us-east-1"

# STS error codes that mean the credential pair itself was rejected (unknown
# access key id, signature mismatch, deactivated key) — distinct from a
# transport failure, throttle, or unrecognized provider-side error, all of
# which fail open to "unknown" rather than being read as a live "invalid"
# verdict. Confirmed against the pinned botocore (1.43.93) by an empirical
# sts:GetCallerIdentity call against AWS's own published example key, which
# returns InvalidClientTokenId over HTTPS 403.
_INVALID_CREDENTIAL_CODES = frozenset(
    {
        "InvalidClientTokenId",
        "SignatureDoesNotMatch",
        "InvalidAccessKeyId",
        "AccessDenied",
        "UnrecognizedClientException",
        "AuthFailure",
    }
)


def _build_sts_client(access_key_id: str, secret_access_key: str) -> Any:
    """Return a boto3 STS client scoped to the discovered credential pair.

    boto3 is an optional (``[aws]``) dependency already pinned by this repo
    for cloud discovery; its absence means live validation cannot run, not
    that the scan should fail. Isolated as its own function so tests can
    monkeypatch it directly instead of mocking boto3/botocore internals.
    """
    import boto3
    from botocore.config import Config

    return boto3.client(
        "sts",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name=_STS_REGION,
        config=Config(
            retries={"max_attempts": 1},
            connect_timeout=_CONNECT_TIMEOUT_SECONDS,
            read_timeout=_READ_TIMEOUT_SECONDS,
        ),
    )


class AwsCredentialValidator:
    """One scan's AWS live-validation budget and digest-only cache.

    Creating an instance performs no I/O. ``validate`` makes at most one
    ``sts:GetCallerIdentity`` read-only call per unique credential pair,
    bounded by ``_MAX_CHECKS`` per scan, and returns whether the pair
    currently authenticates. The access key id, secret access key, and the
    STS response body are never stored beyond the call itself and never
    returned from this method.
    """

    def __init__(self) -> None:
        self._cache: dict[str, ValidationStatus] = {}
        self._checks = 0
        self._blocked = False

    def validate(self, access_key_id: str, secret_access_key: str) -> ValidationStatus:
        digest = hashlib.sha256((access_key_id + "\0" + secret_access_key).encode()).hexdigest()
        if digest in self._cache:
            return self._cache[digest]
        if self._blocked or self._checks >= _MAX_CHECKS:
            return "unknown"
        self._checks += 1
        status = self._check(access_key_id, secret_access_key)
        self._cache[digest] = status
        return status

    def _check(self, access_key_id: str, secret_access_key: str) -> ValidationStatus:
        try:
            client = _build_sts_client(access_key_id, secret_access_key)
        except ImportError:
            self._blocked = True
            return "unknown"

        try:
            client.get_caller_identity()
        except Exception as exc:  # noqa: BLE001 - botocore ClientError/BotoCoreError et al.
            # Match by response shape rather than importing botocore.exceptions,
            # so this module works whether or not the optional AWS extra is
            # installed. Never log or re-raise the exception itself: it can
            # carry request or STS response detail.
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if isinstance(response, dict) else None
            if code in _INVALID_CREDENTIAL_CODES:
                return "invalid"
            # A transport failure, throttle, or unrecognized error establishes
            # neither liveness nor revocation; stop further checks this scan
            # rather than retry into a clearly unreachable/blocked endpoint.
            self._blocked = True
            return "unknown"
        return "valid"
