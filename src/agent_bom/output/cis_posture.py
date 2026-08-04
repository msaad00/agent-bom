"""One derivation of the CIS posture verdict, shared by every renderer.

The console and the HTML report used to compute this independently and
disagreed on the same scan: a bundle of ``[1 pass, 1 error, 0 fail]`` rendered
INCOMPLETE in one and ERROR in the other. Both also printed a green PASS for a
bundle in which nothing was ever evaluated — an account with none of the
resources the benchmark inspects has zero passing controls, not a clean one.
"""

from __future__ import annotations

from typing import Any

from agent_bom.graph.severity import SEVERITY_THRESHOLD_LABELS, severity_worst_first_rank

#: A control only counts as evaluated when it produced a real verdict.
#: ``not_applicable`` and ``skipped`` checks are evidence of nothing.
EVALUATED_STATUSES = ("pass", "fail")

NOT_EVALUATED = "NOT EVALUATED"
ERROR = "ERROR"
INCOMPLETE = "INCOMPLETE"
PASS = "PASS"


def cis_check_tally(checks: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    """Split ``checks`` into the buckets every CIS surface renders from."""
    return {
        "passed": [c for c in checks if str(c.get("status")) == "pass"],
        "failed": [c for c in checks if str(c.get("status")) == "fail"],
        "errored": [c for c in checks if str(c.get("status")) == "error"],
        "evaluated": [c for c in checks if str(c.get("status")) in EVALUATED_STATUSES],
    }


def cis_verdict(checks: list[dict[str, Any]]) -> str:
    """Return the posture verdict for one CIS bundle.

    Ordered so a claim is never stronger than the evidence behind it:

    ``NOT EVALUATED`` no control produced a pass or a fail — nothing was
                      actually checked, so no verdict is earned.
    ``ERROR``         every attempted control errored.
    ``INCOMPLETE``    some controls errored, so coverage has holes.
    ``PASS``          controls were evaluated and none failed.
    ``<SEV> GAPS``    banded by the worst failing control.
    """
    tally = cis_check_tally(checks)
    failed, errored, evaluated = tally["failed"], tally["errored"], tally["evaluated"]

    if not evaluated:
        # Nothing produced a verdict: an errored attempt is a failure to
        # evaluate, an all-not-applicable bundle was never evaluated at all.
        return ERROR if errored else NOT_EVALUATED
    if errored:
        return INCOMPLETE
    if not failed:
        return PASS

    worst = min(failed, key=lambda c: severity_worst_first_rank(c.get("severity")))
    worst_sev = (worst.get("severity") or "low").lower()
    if worst_sev not in SEVERITY_THRESHOLD_LABELS:
        worst_sev = "low"
    return f"{worst_sev.upper()} GAPS"


def cis_pass_rate(bundle: dict[str, Any], checks: list[dict[str, Any]]) -> float:
    """Pass rate over *evaluated* controls, recomputed when the bundle omits it."""
    rate = bundle.get("pass_rate")
    if isinstance(rate, (int, float)):
        return float(rate)
    tally = cis_check_tally(checks)
    evaluated = len(tally["evaluated"])
    return (len(tally["passed"]) / evaluated * 100) if evaluated else 0.0
