"""Write-time gateway rule validation without constraining legacy reads."""

from typing import Any

from pydantic import BaseModel, field_validator

from agent_bom.runtime.policy_validation import validate_policy_rules


class PolicyRuleValidation(BaseModel):
    @field_validator("rules", check_fields=False)
    @classmethod
    def validate_patterns(cls, rules: list[dict[str, Any]] | None) -> list[dict[str, Any]] | None:
        return validate_policy_rules(rules)
