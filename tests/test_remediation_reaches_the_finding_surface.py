"""The advisory we build must carry the fix the check actually shipped.

`cloud_cis_check_to_finding` calls `build_remediation(finding)` on every CIS
finding, producing a structured `Remediation` — fix cli/console, required
privilege, effort, priority, guardrails, generated runbook. Two of its inputs
never arrived:

1. ``remediation_guidance`` was read only from the key ``"recommendation"``,
   while a benchmark check carries its fix under ``"remediation"``. The live
   AWS scanner emits both keys; the demo overlay and several vendor payloads
   emit only the latter — so every one of those findings had null guidance.
2. `_build_cis_remediation` filled the fix from a catalog keyed on control id
   alone and never looked at the check's own ``fix_cli`` / ``fix_console``. The
   copy-pasteable command — the whole point of a structured advisory — came
   back ``None`` and the fix silently degraded to prose.

Both are fixed here, and the check's own block now outranks the generic catalog
entry: it was produced for this resource in this account, where the catalog
entry is generic to the control.

**Not fixed here, deliberately.** The advisory still does not reach
`/v1/findings`, because `redact_for_persistence(..., SAFE_TO_STORE)` strips it
by documented policy: "descriptions, reasons, recommendations, and remediations
are intentionally replay-only because scanners and runtimes often populate them
with copied user/workspace content." That is a data-leakage guard, and
allowlisting the field would weaken it for third-party scanner output in order
to surface our own generated advisory. Telling those two apart needs a
provenance distinction the tier model does not currently make — an owner
decision, not a bug fix. The report/export path is unredacted and gets the full
benefit of this change today.
"""

from __future__ import annotations

from agent_bom.finding import cloud_cis_check_to_finding

FIX_CLI = "aws iam detach-role-policy --role-name prod-admin --policy-arn arn:aws:iam::aws:policy/AdministratorAccess"
FIX_CONSOLE = "IAM > Roles > prod-admin > Permissions"


def cis_check(**overrides: object) -> dict:
    check: dict = {
        "check_id": "1.16",
        "title": "No full-admin IAM policies attached",
        "status": "FAIL",
        "severity": "critical",
        "resource_ids": ["arn:aws:iam::123456789012:role/prod-admin"],
        "cis_section": "1 - Identity and Access Management",
        "remediation": {
            "fix_cli": FIX_CLI,
            "fix_console": FIX_CONSOLE,
            "effort": "low",
            "priority": 1,
            "guardrails": ["Confirm no workload depends on the policy first."],
            "requires_human_review": True,
        },
    }
    check.update(overrides)
    return check


def build(**overrides: object):
    return cloud_cis_check_to_finding(cis_check(**overrides), provider="aws")


def test_the_copy_pasteable_command_reaches_the_advisory() -> None:
    """The defect: fix.cli was None, so the advisory degraded to prose."""
    finding = build()
    assert finding.remediation is not None
    assert finding.remediation.fix.cli == FIX_CLI, finding.remediation.fix.cli


def test_the_console_path_reaches_the_advisory() -> None:
    assert build().remediation.fix.console == FIX_CONSOLE


def test_one_line_guidance_is_derived_when_no_recommendation_is_sent() -> None:
    """A payload carrying only `remediation` used to yield no guidance at all."""
    assert build().remediation_guidance


def test_an_explicit_recommendation_still_wins() -> None:
    """The live scanner sends both keys; its prose must not be overwritten."""
    finding = build(recommendation="Scope the policy to named resources.")
    assert finding.remediation_guidance == "Scope the policy to named resources."


def test_effort_priority_and_guardrails_come_from_the_check() -> None:
    remediation = build().remediation
    assert remediation.effort == "low"
    assert remediation.priority == 1
    assert remediation.guardrails == ["Confirm no workload depends on the policy first."]


def test_a_check_without_its_own_fix_still_gets_an_advisory() -> None:
    """`build_remediation` promises guidance is never dropped; hold it to that."""
    finding = build(remediation=None)
    assert finding.remediation is not None
    assert finding.remediation.fix.summary


def test_the_advisory_never_claims_to_have_been_applied() -> None:
    """Read-only forever: agent-bom recommends, the operator applies."""
    remediation = build().remediation
    assert remediation.applied is False
    assert remediation.auto_remediation is False
    assert remediation.fix.requires_human_review is True


def test_the_advisory_serialises_into_the_report() -> None:
    """The export/report path is unredacted, so the fix lands there today."""
    payload = build().to_dict()
    assert payload["remediation"]["fix"]["cli"] == FIX_CLI
