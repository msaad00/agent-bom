"""Typed error kernel: one vocabulary for rejected, failed and degraded work.

Every agent-bom error that callers are expected to branch on derives from
``AgentBomError``, so ``except AgentBomError`` catches domain failures without
also swallowing programming bugs the way ``except Exception`` does::

    AgentBomError
    ├── ConfigurationError      operator configuration is missing or invalid
    ├── InputError (ValueError) caller-supplied input was rejected
    ├── DataIntegrityError      stored or derived data violates an invariant
    ├── TenantScopeError        work would run without, or across, a tenant scope
    └── UpstreamError           an external source (feed, registry, cloud API) failed
        ├── UpstreamRateLimitedError      throttled; retryable
        ├── UpstreamUnavailableError      5xx, timeout, connection or DNS failure; retryable
        └── UpstreamInvalidResponseError  answered with a body we cannot trust; not retryable

An upstream failure is never an empty answer. A step that finishes with less
data than it asked for returns or records a ``DegradedCoverage`` so the scan
reports partial coverage instead of a confident clean result.

Messages carry only the source name, a fixed reason and numeric status, never
response bodies, URLs or credentials, so ``str(error)`` is safe to log.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any, ClassVar


class AgentBomError(Exception):
    """Root of agent-bom's typed errors."""


class ConfigurationError(AgentBomError):
    """Operator configuration is missing or invalid."""


class InputError(AgentBomError, ValueError):
    """Caller-supplied input was rejected; still a ``ValueError`` for existing handlers."""


class DataIntegrityError(AgentBomError):
    """Stored or derived data violates an invariant the caller relies on."""


class TenantScopeError(AgentBomError):
    """Work would run without, or across, a tenant scope."""


class UpstreamError(AgentBomError):
    """An external source failed to answer.

    ``retryable`` says whether trying later can help; ``affected`` is how many
    requested items (packages, CVEs, catalogs) this one failure left unanswered.
    """

    kind: ClassVar[str] = "upstream_error"
    default_retryable: ClassVar[bool] = False

    def __init__(
        self,
        source: str,
        detail: str = "",
        *,
        status_code: int | None = None,
        retry_after: float | None = None,
        retryable: bool | None = None,
        affected: int = 1,
    ) -> None:
        self.source = source
        self.affected = affected
        self.detail = detail or self.kind.replace("_", " ")
        self.status_code = status_code
        self.retry_after = retry_after
        self.retryable = self.default_retryable if retryable is None else retryable
        super().__init__(f"{source}: {self.detail}")

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"source": self.source, "kind": self.kind, "detail": self.detail, "retryable": self.retryable}
        if self.status_code is not None:
            payload["status_code"] = self.status_code
        if self.retry_after is not None:
            payload["retry_after"] = self.retry_after
        return payload


class UpstreamRateLimitedError(UpstreamError):
    kind = "rate_limited"
    default_retryable = True


class UpstreamUnavailableError(UpstreamError):
    kind = "unavailable"
    default_retryable = True


class UpstreamInvalidResponseError(UpstreamError):
    kind = "invalid_response"


def upstream_error_for_status(
    source: str,
    status_code: int | None,
    *,
    retry_after: float | None = None,
    rate_limit_statuses: frozenset[int] = frozenset({429}),
) -> UpstreamError:
    """Classify a non-success HTTP outcome; ``None`` means no response after retries."""
    if status_code is None:
        return UpstreamUnavailableError(source, "unreachable")
    if status_code in rate_limit_statuses:
        return UpstreamRateLimitedError(source, f"rate limited (HTTP {status_code})", status_code=status_code, retry_after=retry_after)
    if status_code >= 500:
        return UpstreamUnavailableError(source, f"HTTP {status_code}", status_code=status_code, retry_after=retry_after)
    return UpstreamError(source, f"HTTP {status_code}", status_code=status_code)


@dataclass(frozen=True)
class DegradedCoverage:
    """A step finished, but ``missing`` of ``requested`` items could not be retrieved."""

    source: str
    requested: int
    missing: int
    errors: tuple[UpstreamError, ...]
    unit: str = "item(s)"

    @classmethod
    def from_errors(
        cls,
        source: str,
        errors: Iterable[UpstreamError],
        *,
        requested: int,
        missing: int | None = None,
        unit: str = "item(s)",
    ) -> DegradedCoverage | None:
        """Return ``None`` when nothing failed, so callers record only real gaps.

        ``missing`` defaults to the sum of each error's ``affected`` count.
        """
        collected = tuple(errors)
        if missing is None:
            missing = sum(error.affected for error in collected)
        if not collected or missing <= 0:
            return None
        return cls(source=source, requested=requested, missing=min(missing, requested), errors=collected, unit=unit)

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(sorted({error.kind for error in self.errors}))

    @property
    def retryable(self) -> bool:
        return all(error.retryable for error in self.errors)

    def message(self) -> str:
        return f"{self.source} incomplete: {self.missing} of {self.requested} {self.unit} not retrieved ({', '.join(self.kinds)})"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "requested": self.requested,
            "missing": self.missing,
            "unit": self.unit,
            "kinds": list(self.kinds),
            "retryable": self.retryable,
        }
