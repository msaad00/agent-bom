"""Explicitly invoked, bounded, read-only checks of discovered credentials.

Never persist a credential, follow redirects, use ambient proxy credentials, or
read provider response bodies. A verdict describes authentication at check time,
not whether a secret is safe to retain in source. Unsupported types stay unknown.
"""

from __future__ import annotations

import hashlib
import re
from typing import Literal

import httpx

ValidationStatus = Literal["valid", "invalid", "unknown"]
_MAX_CHECKS = 20
_TIMEOUT_SECONDS = 2.0


def _endpoint(secret_type: str, value: str) -> str | None:
    # Installation and refresh tokens cannot be classified by GET /user.
    if secret_type == "GitHub Token" and re.fullmatch(r"gh[pou]_[A-Za-z0-9_]{36,255}", value):
        return "https://api.github.com/user"
    if secret_type == "Stripe Key" and re.fullmatch(r"[sr]k_(live|test)_[A-Za-z0-9]{20,255}", value):
        return "https://api.stripe.com/v1/balance"
    return None


class CredentialValidator:
    """One scan's validation budget and digest-only cache; creating it does no I/O."""

    def __init__(self) -> None:
        self._cache: dict[str, ValidationStatus] = {}
        self._checks = 0
        self._blocked_hosts: set[str] = set()

    def validate(self, secret_type: str, value: str) -> ValidationStatus:
        endpoint = _endpoint(secret_type, value)
        if endpoint is None:
            return "unknown"
        digest = hashlib.sha256((secret_type + "\0" + value).encode()).hexdigest()
        if digest in self._cache:
            return self._cache[digest]
        host = httpx.URL(endpoint).host
        if self._checks >= _MAX_CHECKS or host in self._blocked_hosts:
            return "unknown"
        self._checks += 1
        status: ValidationStatus = "unknown"
        try:
            # Only the fixed provider receives the credential in an auth header.
            # Stream headers only: neither account data nor error bodies enter
            # findings, logs, caches, or memory via an eager response-body read.
            with httpx.Client(timeout=_TIMEOUT_SECONDS, follow_redirects=False, trust_env=False) as client:
                with client.stream(
                    "GET", endpoint, headers={"Authorization": f"Bearer {value}", "User-Agent": "agent-bom-credential-validation"}
                ) as response:
                    if response.status_code == 200:
                        status = "valid"
                    elif response.status_code == 401:
                        status = "invalid"
                    elif response.status_code in {403, 429} or response.status_code >= 500:
                        self._blocked_hosts.add(host)
        except (httpx.HTTPError, OSError):
            # A transport failure cannot establish revocation; never log the
            # exception, which may contain the request or credential material.
            self._blocked_hosts.add(host)
        self._cache[digest] = status
        return status
