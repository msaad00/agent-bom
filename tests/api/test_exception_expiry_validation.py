"""Invalid expiry is rejected at intake, before a pending waiver is stored."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from agent_bom.api.models import ExceptionRequest


@pytest.mark.parametrize("expiry", ["not-a-date", "2020-01-01T00:00:00Z", "2099-01-01T00:00:00", "2099-01-01"])
def test_exception_request_rejects_invalid_expiry(expiry):
    with pytest.raises(ValidationError, match="expires_at"):
        ExceptionRequest(vuln_id="CVE-TEST", package_name="test", expires_at=expiry)


def test_exception_request_preserves_future_expiry_and_unbounded_pending_request():
    expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()
    assert ExceptionRequest(vuln_id="CVE-TEST", package_name="test", expires_at=expiry).expires_at == expiry
    assert ExceptionRequest(vuln_id="CVE-TEST", package_name="test").expires_at == ""
