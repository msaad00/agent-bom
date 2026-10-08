"""Write-time security policy validation without constraining legacy reads."""

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, field_validator

from agent_bom.api.suppression_policy import expiry_window_error
from agent_bom.core.timestamps import parse_identity_timestamp
from agent_bom.runtime.policy_validation import validate_policy_rules


class PolicyRuleValidation(BaseModel):
    @field_validator("rules", check_fields=False)
    @classmethod
    def validate_patterns(cls, rules: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        return validate_policy_rules(rules)


class ExceptionExpiryValidation(BaseModel):
    @field_validator("expires_at", check_fields=False)
    @classmethod
    def validate_expiry(cls, value: str | None) -> str | None:
        # An omitted expiry can remain pending, but never authorizes suppression.
        if not value:
            return value
        expiry = parse_identity_timestamp(value, require_timezone=True)
        if expiry is None or expiry <= datetime.now(timezone.utc):
            raise ValueError("expires_at must be a future timestamp with an explicit timezone")
        if error := expiry_window_error(value):
            raise ValueError(error)
        return value
