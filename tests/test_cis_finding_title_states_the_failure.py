"""A failing control must not be titled with the state it failed to reach.

CIS phrases every control as an assertion of the *desired* state — "No root
account access keys", "Root account MFA enabled", "No full-admin IAM policies
attached". That is correct for a control name and wrong for a finding title,
because a finding exists precisely when the assertion is false.

`finding.py` composed the title as ``f"CIS {check_id}: {title}"``, so 1,581
FAIL findings on the demo estate rendered as, verbatim:

    critical    CIS 1.16: No full-admin IAM policies attached

A reader scanning that list sees a critical finding whose headline says the
thing they are worried about is not happening. The rest of the record already
knew better — ``finding_type`` is ``CIS_FAIL``, ``evidence["status"]`` is
``"FAIL"``, and the description reads "control 1.16 failed for aws". Only the
title, the one field that gets read first and quoted into tickets and exports,
stated the opposite.

The outcome now travels in the title:

    CIS 1.16 not met: No full-admin IAM policies attached
    CIS 1.16 not evaluated: No full-admin IAM policies attached   (status ERROR)

Phrasing it as "not met" rather than negating the control name is deliberate:
CIS control names are assertions, so "<control> not met" is grammatical for all
of them, where mechanical negation ("No root account access keys" -> ?) is not.

The control name itself stays intact after the colon and in
``evidence["control_title"]``, so anything mapping a finding back to its
benchmark control keeps working.
"""

from __future__ import annotations

import pytest

from agent_bom.finding import cloud_cis_check_to_finding


def cis_check(**overrides: object) -> dict:
    check = {
        "check_id": "1.16",
        "title": "No full-admin IAM policies attached",
        "status": "FAIL",
        "severity": "critical",
        "evidence": "attached_policy_actions on prod-admin is Action '*' on Resource '*'",
        "resource_ids": ["arn:aws:iam::123456789012:role/prod-admin"],
        "recommendation": "Scope the policy down.",
        "cis_section": "1 - Identity and Access Management",
        "account_id": "123456789012",
    }
    check.update(overrides)
    return check


def build(**overrides: object):
    return cloud_cis_check_to_finding(cis_check(**overrides), provider="aws")


def test_a_failing_control_is_not_titled_as_if_it_passed() -> None:
    finding = build()
    assert finding.title != "CIS 1.16: No full-admin IAM policies attached"
    assert "not met" in finding.title, finding.title


def test_the_title_still_names_the_control_and_its_id() -> None:
    """Traceability to the benchmark must survive the rewording."""
    finding = build()
    assert "1.16" in finding.title
    assert "No full-admin IAM policies attached" in finding.title
    assert finding.evidence["control_title"] == "No full-admin IAM policies attached"


def test_an_unevaluated_control_says_so_rather_than_claiming_failure() -> None:
    """ERROR is not FAIL. Claiming a control failed when it could not be read
    is the same class of dishonesty in the other direction."""
    finding = build(status="ERROR", severity="")
    assert "not evaluated" in finding.title, finding.title
    assert "not met" not in finding.title


@pytest.mark.parametrize(
    "control",
    [
        "Root account MFA enabled",
        "No root account access keys",
        "IAM password policy minimum length >= 14",
        "MFA on all console-access IAM users",
    ],
)
def test_the_phrasing_reads_correctly_for_real_control_names(control: str) -> None:
    """Every one of these is an assertion of the good state, taken from the
    live AWS benchmark. "<control> not met" has to work for all of them."""
    finding = build(title=control)
    assert finding.title.endswith(f": {control}")
    assert "not met" in finding.title


def test_a_vendor_best_practice_keeps_its_own_label() -> None:
    finding = cloud_cis_check_to_finding(
        cis_check(title="Unity Catalog enabled on all workspaces"),
        provider="databricks",
    )
    assert "Databricks best practice" in finding.title
    assert "not met" in finding.title


def test_the_outcome_is_in_the_title_not_only_the_evidence() -> None:
    """When a check ships its own evidence text, that becomes the description —
    so the fallback sentence naming the failure never renders. The title is then
    the only place the outcome appears at all, which is why it has to carry it."""
    finding = build()
    assert "action" in finding.description.lower()
    assert "failed" not in finding.description.lower()
    assert "not met" in finding.title
