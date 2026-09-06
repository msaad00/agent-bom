"""Source-scoped authority derived from an already verified credential."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from urllib.parse import quote

MAX_RUNTIME_CREDENTIAL_TTL_SECONDS = 3600


class SourceAuthenticationError(RuntimeError):
    """A credential cannot authorize the requested runtime evidence source."""


def runtime_source_scope(source_id: str) -> str:
    """An exact source grant; wildcard grants deliberately do not substitute."""
    return f"runtime:ingest:{quote(source_id, safe='')}"


@dataclass(frozen=True)
class RuntimeSourcePrincipal:
    """Internal authority built only after transport credential verification.

    This is not an HTTP input model. Scopes, identity and lifetime must come
    from the verified JWT or persisted key record, never evidence parameters.
    """

    subject: str
    tenant_id: str
    scopes: tuple[str, ...]
    issued_at: float
    expires_at: float

    def authorize(self, source_id: str, tenant_id: str) -> None:
        now = time.time()
        if (
            not self.subject.strip()
            or not self.tenant_id.strip()
            or self.tenant_id != tenant_id
            or runtime_source_scope(source_id) not in self.scopes
            or type(self.issued_at) not in (int, float)
            or type(self.expires_at) not in (int, float)
            or not math.isfinite(self.issued_at)
            or not math.isfinite(self.expires_at)
            or self.issued_at > now
            or self.expires_at <= now
            or not 0 < self.expires_at - self.issued_at <= MAX_RUNTIME_CREDENTIAL_TTL_SECONDS
        ):
            raise SourceAuthenticationError("runtime evidence source authentication failed")
