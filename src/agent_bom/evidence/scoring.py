"""One derivation of the compliance top line — status AND score, together.

Every surface that reports compliance posture needs the same judgement: given
what a scan actually evaluated, is there a score worth showing, and what is it?
That judgement was reimplemented independently on the REST aggregate, the
per-framework REST route, the MCP tool, the HTML report, the signed evidence
bundle, and the Overview cockpit. Each copy drifted, and a guard added to one
left the other five reporting a green ``100% / PASS`` over an estate where
nothing had been measured.

The judgement itself has two parts, and both must be made in the same place:

* **A pass is only meaningful if something SUBSTANTIVE was evaluated.** A
  DETECTIVE control (see :mod:`agent_bom.evidence.control_modes`) passes because
  a scan ran — it is evidence about the monitoring program, not about whether
  the estate meets a framework. An estate whose every passing control is
  detective has been shown to be scanned, not compliant, so it reports
  ``no_data``.
* **``no_data`` means there is no score.** Splitting the two derivations is what
  let ``overall_status="no_data"`` sit beside ``overall_score=100.0``: the score
  was ``passed / evaluated`` (8/8 detective passes) while the status keyed off
  ``substantive_evaluated``. Deriving the score FROM the status makes that
  disagreement unrepresentable.

``0.0`` — not ``None`` — is the repo-wide score for an unevidenced estate,
matching what the per-framework route, the signed bundle, and the evidence pack
already emit. It is never rendered bare: every surface pairs it with the
``no_data`` status, and the UI renders an em dash rather than "0%".
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = [
    "STATUS_PASS",
    "STATUS_WARNING",
    "STATUS_FAIL",
    "STATUS_NO_DATA",
    "ComplianceVerdict",
    "score_compliance",
]

STATUS_PASS = "pass"
STATUS_WARNING = "warning"
STATUS_FAIL = "fail"
STATUS_NO_DATA = "no_data"


@dataclass(frozen=True)
class ComplianceVerdict:
    """The top line for one framework or one aggregate.

    ``score`` is a percentage of EVALUATED controls, so it is only honest beside
    ``evaluated`` — every surface that renders one must render the other.
    """

    status: str
    score: float
    evaluated: int
    substantive_evaluated: int

    @property
    def is_evaluated(self) -> bool:
        """False when there is nothing to report — render an em dash, not a number."""
        return self.status != STATUS_NO_DATA


def score_compliance(
    *,
    passed: int,
    warned: int,
    failed: int,
    errored: int = 0,
    detective_passes: int = 0,
    has_evidence: bool = True,
) -> ComplianceVerdict:
    """Derive ``(status, score)`` from what a scan evaluated.

    Args:
        passed / warned / failed: evaluated controls by outcome.
        errored: controls that could not be evaluated (a benchmark ERROR). They
            count toward the denominator — an unevaluable control drags the
            score down — but are never a pass.
        detective_passes: how many of ``passed`` are detective controls, i.e.
            passing only because a scan ran. Subtracted to decide whether
            anything substantive was measured.
        has_evidence: False when no completed scan exists at all, in which case
            every control trivially lacks findings and no count means anything.

    Raises:
        ValueError: if ``detective_passes`` exceeds ``passed``, or any count is
            negative — a caller miscounting its own controls would otherwise
            silently produce a wrong top line.
    """
    counts = {"passed": passed, "warned": warned, "failed": failed, "errored": errored, "detective_passes": detective_passes}
    for name, value in counts.items():
        if value < 0:
            raise ValueError(f"{name} must be non-negative, got {value}")
    if detective_passes > passed:
        raise ValueError(f"detective_passes ({detective_passes}) cannot exceed passed ({passed})")

    evaluated = passed + warned + failed + errored
    substantive_evaluated = evaluated - detective_passes

    if not has_evidence:
        status = STATUS_NO_DATA
    elif failed > 0:
        status = STATUS_FAIL
    elif warned > 0 or errored > 0:
        status = STATUS_WARNING
    elif substantive_evaluated > 0:
        status = STATUS_PASS
    else:
        status = STATUS_NO_DATA

    # Derived FROM the status, never re-derived from a second condition.
    score = 0.0 if status == STATUS_NO_DATA else round((passed / evaluated) * 100, 1)

    return ComplianceVerdict(
        status=status,
        score=score,
        evaluated=evaluated,
        substantive_evaluated=substantive_evaluated,
    )
