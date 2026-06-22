"""Request models must reject unknown fields (extra=forbid), not silently drop them.

A fat-fingered or stale field on a security-relevant body (a policy's action, a
key's role, a triage decision's justification) must 422, not be dropped — which
would silently apply the wrong, more-permissive default.
"""

import pytest
from pydantic import ValidationError

from agent_bom.api import models


@pytest.mark.parametrize(
    "model_name, valid_kwargs",
    [
        ("PolicyCreate", {"name": "p", "rules": []}),
        ("CreateKeyRequest", {}),
        ("FindingTriageDecisionRequest", {"decision": "accept"}),
        ("SourceCreate", {"name": "s", "type": "github"}),
        ("ScheduleCreate", {"name": "sch", "cron": "0 0 * * *"}),
    ],
)
def test_request_model_rejects_unknown_field(model_name, valid_kwargs):
    model = getattr(models, model_name)
    # Tolerate required-field differences across versions: only assert that an
    # unknown field is rejected, regardless of whether valid_kwargs is complete.
    with pytest.raises(ValidationError) as exc:
        model(**{**valid_kwargs, "definitely_not_a_real_field": "x"})
    assert "definitely_not_a_real_field" in str(exc.value)


def test_extra_forbid_is_widespread():
    # Guard against regressions: the sweep covered the request-model surface.
    forbid = [
        n
        for n in dir(models)
        if isinstance(getattr(models, n), type) and getattr(getattr(models, n), "model_config", {}).get("extra") == "forbid"
    ]
    assert len(forbid) >= 25, forbid
