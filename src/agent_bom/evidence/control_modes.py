"""Evaluation mode per compliance control — detective vs corrective.

A control's *evidence semantics* decide what a scan result means for it. Scoring
every mapped control the same way ("a finding maps here, therefore the control
FAILS") is only correct for one of the two classes, and it produced the
indefensible reads this module exists to remove:

* **DETECTIVE** controls — "Monitor and scan for vulnerabilities in the system
  and hosted applications" (NIST ``RA-5``), "Develop and document an inventory
  of system components" (``CM-8``), "Vulnerabilities in assets are identified"
  (CSF ``ID.RA-01``) — are *implemented by* the scan itself. Producing this scan
  and this SBOM IS the evidence the control operates, so a completed, in-window
  scan scores ``pass``. Findings mapped to such a control prove it works; they
  are never proof it failed. Evidence older than
  :data:`~agent_bom.config.COMPLIANCE_DETECTIVE_EVIDENCE_MAX_AGE_DAYS` scores
  ``fail`` — the control has stopped operating.

* **CORRECTIVE / PREVENTIVE** controls — flaw remediation (``SI-2``), supply
  chain controls (``SR-3``), input validation (``SI-10``), authenticator
  management (``IA-5``) — are attested by the ABSENCE of an open weakness. An
  open finding scores fail/warning by worst severity; a scan that produced no
  mapped finding stays ``not_evaluated``, because absence of a CVE is not proof
  the control is implemented. This is the default for any control not listed
  here.

* **UNEVALUABLE** controls — "Respond to findings from security assessments"
  (``RA-7``), "Track and document incidents" (``IR-5``) — describe an
  organizational process a package scan cannot observe in either direction.
  They are never asserted from finding data at all; the taggers skip them and
  they surface as ``not_evaluated`` against the full catalog.

Keyed by the blast-radius/finding tag field (``compliance_coverage.tag_field``)
so every surface — API, CLI narrative, exports, MCP — resolves a control's mode
through one table.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime, timedelta, timezone

__all__ = [
    "DETECTIVE_CONTROLS",
    "UNEVALUABLE_CONTROLS",
    "MODE_DETECTIVE",
    "MODE_CORRECTIVE",
    "control_evaluation_mode",
    "is_detective_control",
    "detective_control_status",
    "finding_taggable_controls",
]

MODE_DETECTIVE = "detective"
MODE_CORRECTIVE = "corrective"


# tag_field -> control IDs whose objective is "we monitor / scan / inventory".
# A completed scan is affirmative evidence these operate.
DETECTIVE_CONTROLS: dict[str, frozenset[str]] = {
    # NIST SP 800-53 Rev 5
    #   RA-5 "Vulnerability Monitoring and Scanning"
    #   CM-8 "System Component Inventory"
    "nist_800_53_tags": frozenset({"RA-5", "CM-8"}),
    # NIST CSF 2.0
    #   ID.RA-01 "Vulnerabilities in assets are identified"
    #   ID.RA-02 "Cyber threat intelligence received from information sharing forums"
    #   DE.CM-09 "Computing hardware and software are monitored for vulnerabilities"
    "nist_csf_tags": frozenset({"ID.RA-01", "ID.RA-02", "DE.CM-09"}),
    # CIS Controls v8 (agent-bom's own descriptors — see cis_controls.py)
    #   CIS-02.1 software asset inventory
    #   CIS-07.1 vulnerability-management program
    #   CIS-07.5 internal-asset vulnerability scanning
    "cis_tags": frozenset({"CIS-02.1", "CIS-07.1", "CIS-07.5"}),
}


# tag_field -> control IDs a dependency/CVE scan cannot observe in either
# direction. Never asserted from finding data.
UNEVALUABLE_CONTROLS: dict[str, frozenset[str]] = {
    # RA-7 "Risk Response" — whether the organization responds to findings.
    # IR-5 "Incident Monitoring" — whether incidents are tracked and documented.
    "nist_800_53_tags": frozenset({"RA-7", "IR-5"}),
}


def control_evaluation_mode(tag_field: str, control_id: str) -> str:
    """Return ``"detective"`` or ``"corrective"`` for one control.

    Corrective is the default: a control is only detective when this module
    explicitly asserts the scan itself evidences it.
    """
    if control_id in DETECTIVE_CONTROLS.get(tag_field, frozenset()):
        return MODE_DETECTIVE
    return MODE_CORRECTIVE


def is_detective_control(tag_field: str, control_id: str) -> bool:
    """True when a completed scan is affirmative evidence for ``control_id``."""
    return control_id in DETECTIVE_CONTROLS.get(tag_field, frozenset())


def finding_taggable_controls(tag_field: str, control_ids: Iterable[str]) -> set[str]:
    """Drop the controls a finding must never be tagged onto.

    Detective controls are evidenced by the scan (tagging a finding onto them
    would fail the control that produced the evidence); unevaluable controls
    cannot be observed at all. Applied as the last step of every tagger so a
    CWE-table entry cannot re-introduce one through the back door.
    """
    excluded = DETECTIVE_CONTROLS.get(tag_field, frozenset()) | UNEVALUABLE_CONTROLS.get(tag_field, frozenset())
    return {control_id for control_id in control_ids if control_id not in excluded}


# Forward clock drift between a scanner host and the control plane that is
# ordinary NTP skew rather than an untrustworthy timestamp.
_MAX_FORWARD_CLOCK_SKEW = timedelta(minutes=5)


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def detective_control_status(
    *,
    scan_count: int,
    latest_scan: str | None,
    now: datetime | None = None,
    max_age_days: int | None = None,
) -> tuple[str, str]:
    """Score a detective control from scan evidence. Returns ``(status, reason)``.

    * No completed scan — ``("not_assessed", "no_completed_scan")``. Nothing was
      measured, so the control is not asserted to fail; the aggregate top-line
      already reports ``no_data`` for this state.
    * A completed scan inside the freshness window —
      ``("pass", "fresh_scan_evidence")``. The scan IS the control operating.
    * A completed scan older than the window —
      ``("fail", "stale_scan_evidence")``. Continuous monitoring has lapsed.
    * A completed scan with no usable timestamp (missing, empty, or
      unparseable) — ``("not_assessed", "scan_evidence_age_unknown")``. The
      whole claim a detective pass makes is that monitoring is CURRENT, and that
      rests entirely on the timestamp. Evidence we cannot date is not evidence
      that the control operates now, so it is not asserted in either direction.
      This previously returned ``pass``, which meant a DONE job with
      ``completed_at=None`` produced a fully green scorecard.
    * A completed scan dated in the FUTURE beyond ordinary clock skew —
      ``("fail", "future_scan_evidence")``. ``reference - completed`` is
      negative for a future timestamp and so can never exceed the window: a scan
      dated +10 years read as fresh on every subsequent request, permanently.
    """
    from agent_bom import config

    if scan_count <= 0:
        return "not_assessed", "no_completed_scan"

    window_days = config.COMPLIANCE_DETECTIVE_EVIDENCE_MAX_AGE_DAYS if max_age_days is None else max_age_days
    if window_days <= 0:
        return "pass", "fresh_scan_evidence"

    completed = _parse_timestamp(latest_scan)
    if completed is None:
        return "not_assessed", "scan_evidence_age_unknown"

    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    age = reference - completed
    if age > timedelta(days=window_days):
        return "fail", "stale_scan_evidence"
    # Tolerate ordinary NTP drift between a scanner and the control plane; a
    # timestamp further ahead than that is not a datable scan.
    if -age > _MAX_FORWARD_CLOCK_SKEW:
        return "fail", "future_scan_evidence"
    return "pass", "fresh_scan_evidence"
