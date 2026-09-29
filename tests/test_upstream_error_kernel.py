"""The typed error kernel classifies upstream failures and never reports a gap as clean."""

from __future__ import annotations

import pytest

from agent_bom.core.errors import (
    AgentBomError,
    ConfigurationError,
    DataIntegrityError,
    DegradedCoverage,
    InputError,
    TenantScopeError,
    UpstreamError,
    UpstreamInvalidResponseError,
    UpstreamRateLimitedError,
    UpstreamUnavailableError,
    upstream_error_for_status,
)


def test_hierarchy_shares_one_root_and_input_errors_stay_value_errors():
    for cls in (ConfigurationError, InputError, DataIntegrityError, TenantScopeError, UpstreamError):
        assert issubclass(cls, AgentBomError)
    for cls in (UpstreamRateLimitedError, UpstreamUnavailableError, UpstreamInvalidResponseError):
        assert issubclass(cls, UpstreamError)
    assert issubclass(InputError, ValueError)
    with pytest.raises(ValueError):
        raise InputError("bad ecosystem")


@pytest.mark.parametrize(
    ("status", "expected", "retryable"),
    [
        (None, UpstreamUnavailableError, True),
        (429, UpstreamRateLimitedError, True),
        (500, UpstreamUnavailableError, True),
        (503, UpstreamUnavailableError, True),
        (400, UpstreamError, False),
        (401, UpstreamError, False),
    ],
)
def test_status_classification(status, expected, retryable):
    error = upstream_error_for_status("osv", status, retry_after=3.0)
    assert type(error) is expected
    assert error.retryable is retryable
    assert error.source == "osv"
    assert error.status_code == status


def test_custom_rate_limit_statuses_cover_sources_that_throttle_with_403():
    error = upstream_error_for_status("nvd", 403, rate_limit_statuses=frozenset({403, 429}))
    assert isinstance(error, UpstreamRateLimitedError)
    assert error.to_dict() == {
        "source": "nvd",
        "kind": "rate_limited",
        "detail": "rate limited (HTTP 403)",
        "retryable": True,
        "status_code": 403,
    }


def test_invalid_response_is_not_retryable_and_message_is_bounded():
    error = UpstreamInvalidResponseError("epss", "unexpected payload shape")
    assert error.retryable is False
    assert str(error) == "epss: unexpected payload shape"


def test_degraded_coverage_only_exists_for_real_gaps():
    assert DegradedCoverage.from_errors("EPSS", [], requested=10, missing=0) is None
    assert DegradedCoverage.from_errors("EPSS", [UpstreamRateLimitedError("epss")], requested=10, missing=0) is None
    degraded = DegradedCoverage.from_errors(
        "EPSS",
        [UpstreamRateLimitedError("epss"), UpstreamInvalidResponseError("epss")],
        requested=10,
        missing=40,
        unit="CVE(s)",
    )
    assert degraded is not None
    assert degraded.missing == 10
    assert degraded.kinds == ("invalid_response", "rate_limited")
    assert degraded.retryable is False
    assert degraded.message() == "EPSS incomplete: 10 of 10 CVE(s) not retrieved (invalid_response, rate_limited)"
    assert degraded.to_dict()["kinds"] == ["invalid_response", "rate_limited"]
