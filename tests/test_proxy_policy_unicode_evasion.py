"""A look-alike tool name must not walk past the shipped gateway baseline.

``check_policy_detail`` compared tool names as raw strings, so a caller could
rename ``delete_file`` to ``dеlete_file`` (Cyrillic ``е``), splice in a
zero-width space, or send it fullwidth and every deny rule in
``baseline_gateway_rules()`` — the policy operators actually ship — missed it.
The product already normalized text for tool-poisoning *detection*; enforcement
just never used it.

The two directions are deliberately asymmetric, and both are fail-closed:

* a deny rule matches the normalized name as well as the raw one, so an evasion
  is caught;
* an allowlist is NOT satisfied by a look-alike — ``rеad_file`` is not the tool
  the operator allowed, so it stays denied.
"""

from __future__ import annotations

import pytest

from agent_bom.gateway_policy_templates import baseline_gateway_rules
from agent_bom.proxy_policy import check_policy, check_policy_detail

ZWSP = "​"
CYRILLIC_E = "е"
FULLWIDTH_DELETE = "ｄｅｌｅｔｅ"

EVASIONS = [
    pytest.param(f"d{ZWSP}elete_file", id="zero-width-space"),
    pytest.param(f"d{CYRILLIC_E}lete_file", id="cyrillic-homoglyph"),
    pytest.param(f"{FULLWIDTH_DELETE}_file", id="fullwidth"),
    pytest.param("DELETE_FILE", id="uppercase"),
    pytest.param(f"D{CYRILLIC_E.upper()}LETE_FILE", id="cyrillic-uppercase"),
]


def _baseline() -> dict:
    return {"rules": [rule.model_dump() for rule in baseline_gateway_rules()]}


def test_the_plain_name_is_blocked_by_the_shipped_baseline():
    """The control being evaded — if this ever fails the rest proves nothing."""
    allowed, reason = check_policy(_baseline(), "delete_file", {})
    assert allowed is False, reason


@pytest.mark.parametrize("tool_name", EVASIONS)
def test_unicode_evasions_of_a_denied_tool_are_blocked(tool_name: str):
    allowed, reason = check_policy(_baseline(), tool_name, {})
    assert allowed is False, f"{tool_name!r} walked past the baseline: {reason}"


@pytest.mark.parametrize("tool_name", EVASIONS)
def test_unicode_evasions_do_not_escape_an_explicit_block_list(tool_name: str):
    policy = {"rules": [{"id": "no-delete", "action": "block", "block_tools": ["delete_file"]}]}

    allowed, reason, rule_id = check_policy_detail(policy, tool_name, {})

    assert allowed is False, f"{tool_name!r} escaped block_tools: {reason}"
    assert rule_id == "no-delete"


@pytest.mark.parametrize("tool_name", EVASIONS)
def test_unicode_evasions_do_not_escape_an_exact_tool_name_rule(tool_name: str):
    policy = {"rules": [{"id": "exact", "action": "block", "tool_name": "delete_file"}]}

    allowed, _reason, rule_id = check_policy_detail(policy, tool_name, {})

    assert allowed is False
    assert rule_id == "exact"


@pytest.mark.parametrize("tool_name", EVASIONS)
def test_unicode_evasions_do_not_escape_a_blocked_name_pattern(tool_name: str):
    policy = {"rules": [{"id": "pattern", "action": "block", "tool_name_pattern": "^delete_"}]}

    allowed, _reason, rule_id = check_policy_detail(policy, tool_name, {})

    assert allowed is False
    assert rule_id == "pattern"


def test_a_look_alike_does_not_satisfy_an_allowlist():
    """Normalization must never be a way INTO an allowlist.

    Folding both sides of an allowlist comparison would turn a homoglyph into a
    key that unlocks the allowed tool. An allowlist stays an exact match: the
    look-alike is not the tool the operator allowed.
    """
    policy = {"rules": [{"id": "only-read", "mode": "allowlist", "action": "block", "allow_tools": ["read_file"]}]}

    assert check_policy(policy, "read_file", {})[0] is True
    for evasion in (f"r{CYRILLIC_E}ad_file", f"r{ZWSP}ead_file", "READ_FILE"):
        allowed, reason = check_policy(policy, evasion, {})
        assert allowed is False, f"{evasion!r} satisfied the allowlist: {reason}"


def test_ordinary_read_tools_are_still_allowed_by_the_baseline():
    """The fix must not start denying tools the baseline has always permitted."""
    for tool_name in ("read_file", "list_directory", "get_status"):
        allowed, reason = check_policy(_baseline(), tool_name, {})
        assert allowed is True, f"{tool_name} regressed to denied: {reason}"


def test_enforcement_and_policy_share_one_normalizer():
    """No second normalizer: the poisoning scanner and the gateway agree."""
    from agent_bom import enforcement
    from agent_bom.runtime import text_normalize

    assert enforcement._normalize_text is text_normalize.normalize_text


def test_the_shared_normalizer_keeps_its_detection_behaviour():
    """Lifting it out of enforcement.py must not change what detection sees."""
    from agent_bom.runtime.text_normalize import normalize_text

    assert normalize_text(f"ignore{ZWSP} previous") == "ignore previous"
    assert normalize_text("ｉｇｎｏｒｅ") == "ignore"
