"""Alert deduplication and suppression.

Prevents the same vulnerability from generating multiple alerts
within a configurable suppression window.

Dedup key: SHA-256(vuln_id + package + severity)
Suppression: configurable TTL (default 24 hours)
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DedupEntry:
    """Tracks a deduplicated alert."""

    fingerprint: str
    first_seen: float
    last_seen: float
    count: int = 1
    suppressed: int = 0


class AlertDeduplicator:
    """Deduplicates alerts based on content fingerprinting.

    Alerts with the same fingerprint (vuln_id + package + severity)
    within the suppression window are merged into a single alert
    with an incremented count.
    """

    def __init__(
        self,
        suppression_window_seconds: int = 86400,  # 24 hours
        max_entries: int = 10_000,
    ) -> None:
        self._window = suppression_window_seconds
        self._max_entries = max_entries
        self._seen: OrderedDict[str, DedupEntry] = OrderedDict()
        self._lock = threading.Lock()

    def fingerprint(self, alert: dict) -> str:
        """Compute a dedup fingerprint for an alert."""
        details = alert.get("details", {})
        parts = [
            details.get("vuln_id", alert.get("message", "")),
            details.get("package", ""),
            alert.get("severity", ""),
            alert.get("detector", ""),
        ]
        return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]

    def should_send(self, alert: dict) -> bool:
        """Check if an alert should be dispatched or suppressed.

        Returns True if the alert is new or outside the suppression window.
        """
        fp = self.fingerprint(alert)
        now = time.monotonic()

        with self._lock:
            self._evict_expired(now)

            entry = self._seen.get(fp)
            if entry is None:
                # New alert — allow
                self._seen[fp] = DedupEntry(fingerprint=fp, first_seen=now, last_seen=now)
                self._enforce_size_limit()
                return True

            # Existing alert — check window
            if now - entry.first_seen > self._window:
                # Window expired — reset and allow
                entry.first_seen = now
                entry.last_seen = now
                entry.count = 1
                entry.suppressed = 0
                self._seen.move_to_end(fp)
                return True

            # Within window — suppress
            entry.last_seen = now
            entry.count += 1
            entry.suppressed += 1
            return False

    def get_stats(self) -> dict:
        """Return dedup statistics."""
        with self._lock:
            total = len(self._seen)
            total_suppressed = sum(e.suppressed for e in self._seen.values())
            return {
                "tracked_fingerprints": total,
                "total_suppressed": total_suppressed,
                "window_seconds": self._window,
            }

    def _evict_expired(self, now: float) -> None:
        """Remove entries older than the suppression window."""
        expired = [fp for fp, entry in self._seen.items() if now - entry.last_seen > self._window]
        for fp in expired:
            del self._seen[fp]

    def _enforce_size_limit(self) -> None:
        while len(self._seen) > self._max_entries:
            self._seen.popitem(last=False)
