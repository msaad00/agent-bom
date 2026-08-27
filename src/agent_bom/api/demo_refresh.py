"""Keep UTC-day-scoped demo evidence current on the surfaces that window on it.

The gateway KPI header, proxy status, firewall stats, the runtime production
index and the cost page all report over ``[UTC midnight, request time]``. Demo
evidence seeded at boot carries the boot day's timestamps, so once the UTC day
advances every one of those surfaces reads 0 — a demo asserting no traffic on an
estate the same page describes as busy.

This module is the single seam that closes that gap for all of them. It stays
here, rather than in ``demo_estate``, so route modules import an ``api`` sibling
and the demo package is only touched behind a lazy import — no import cycle, and
nothing outside demo mode pays more than one environment lookup per request.
"""

from __future__ import annotations

import logging

_logger = logging.getLogger(__name__)


def demo_daily_evidence_dependency() -> None:
    """Route dependency: refresh day-scoped demo evidence before serving.

    A no-op outside demo mode, and one string compare once the day is current.
    Never raises: a demo refresh must not be able to fail a real request.
    """
    try:
        from agent_bom.demo_estate.bootstrap import refresh_demo_daily_evidence

        refresh_demo_daily_evidence()
    except Exception:  # noqa: BLE001 - a demo refresh must never fail a request
        _logger.warning("demo estate daily evidence refresh skipped", exc_info=False)
