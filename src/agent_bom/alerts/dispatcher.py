"""Central alert dispatcher with pluggable delivery channels.

Routes :class:`Alert` objects (from runtime detectors) and plain dicts
(from scan findings) to one or more delivery channels: in-memory ring
buffer, Slack webhook, generic HTTP webhook.
"""

from __future__ import annotations

import asyncio
import logging
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

logger = logging.getLogger(__name__)


# ─── Channel Protocol ────────────────────────────────────────────────────────


@runtime_checkable
class AlertChannel(Protocol):
    """Protocol for alert delivery channels."""

    async def send(self, alert: dict) -> bool: ...


# ─── In-Memory Channel ───────────────────────────────────────────────────────


class InMemoryChannel:
    """Bounded ring buffer for API-accessible alert history.

    Always present in the dispatcher — provides ``GET /v1/alerts`` data.
    """

    def __init__(self, max_size: int = 1000) -> None:
        self._max_size = max_size
        self._buffer: deque[dict] = deque(maxlen=max_size)

    async def send(self, alert: dict) -> bool:
        self._buffer.appendleft(alert)
        return True

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        detector: str | None = None,
    ) -> list[dict]:
        """Return alerts with optional filtering."""
        items: list[dict] = list(self._buffer)
        if severity:
            items = [a for a in items if a.get("severity") == severity]
        if detector:
            items = [a for a in items if a.get("detector") == detector]
        return items[offset : offset + limit]

    def count(self) -> int:
        return len(self._buffer)

    def stats(self) -> dict:
        """Aggregate counts by severity and detector."""
        by_severity: dict[str, int] = {}
        by_detector: dict[str, int] = {}
        for a in self._buffer:
            sev = a.get("severity", "unknown")
            det = a.get("detector", "unknown")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            by_detector[det] = by_detector.get(det, 0) + 1
        return {
            "total": len(self._buffer),
            "by_severity": by_severity,
            "by_detector": by_detector,
        }


# ─── Slack Channel ────────────────────────────────────────────────────────────


class SlackChannel:
    """Route alerts to Slack via incoming webhook.

    Reuses the existing ``send_slack_payload()`` helper when available,
    falls back to a direct httpx POST.
    """

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def send(self, alert: dict) -> bool:
        try:
            from agent_bom.integrations.slack import send_slack_payload

            payload = _build_slack_payload(alert)
            return send_slack_payload(self.webhook_url, payload)
        except Exception:
            logger.exception("Slack channel delivery failed")
            return False


def _build_slack_payload(alert: dict) -> dict:
    """Convert an alert dict into Slack Block Kit format."""
    severity = alert.get("severity", "info").upper()
    message = alert.get("message", "")
    detector = alert.get("detector", "")
    ts = alert.get("ts", "")
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}.get(severity, "ℹ️")
    return {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *{severity}* — {message}",
                },
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"Detector: `{detector}` | {ts}"},
                ],
            },
        ],
    }


# ─── Generic Webhook Channel ─────────────────────────────────────────────────


class WebhookChannel:
    """Generic HTTP POST webhook for PagerDuty, Teams, custom endpoints."""

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = headers or {}

    async def send(self, alert: dict) -> bool:
        try:
            import httpx

            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    self.url,
                    json=alert,
                    headers={"Content-Type": "application/json", **self.headers},
                )
                return resp.status_code < 400
        except Exception:
            logger.exception("Webhook channel delivery failed for %s", self.url)
            return False


# ─── Dispatcher ───────────────────────────────────────────────────────────────


@dataclass
class DispatcherStats:
    """Lifetime dispatch statistics."""

    total_dispatched: int = 0
    total_channel_failures: int = 0
    channels_registered: int = 1  # InMemoryChannel is always present


class AlertDispatcher:
    """Central alert router. Thread-safe via asyncio.

    Always includes an :class:`InMemoryChannel` for API access.
    Additional channels (Slack, webhook) are opt-in.
    """

    def __init__(self) -> None:
        self._in_memory = InMemoryChannel()
        self._channels: list[AlertChannel] = [self._in_memory]
        self._webhooks: list[WebhookChannel] = []
        self._stats = DispatcherStats()

    def add_channel(self, channel: AlertChannel) -> None:
        self._channels.append(channel)
        self._stats.channels_registered += 1

    def add_webhook(self, url: str, headers: dict[str, str] | None = None) -> None:
        ch = WebhookChannel(url, headers)
        self._webhooks.append(ch)
        self._channels.append(ch)
        self._stats.channels_registered += 1

    def remove_webhooks(self) -> int:
        """Remove all registered webhook channels. Returns count removed."""
        count = len(self._webhooks)
        for wh in self._webhooks:
            if wh in self._channels:
                self._channels.remove(wh)
        self._webhooks.clear()
        return count

    def add_slack(self, webhook_url: str) -> None:
        ch = SlackChannel(webhook_url)
        self._channels.append(ch)
        self._stats.channels_registered += 1

    async def dispatch(self, alert: object) -> int:
        """Route alert to all channels. Returns number of successful deliveries."""
        if hasattr(alert, "to_dict"):
            alert_dict = alert.to_dict()  # type: ignore[union-attr]
        elif isinstance(alert, dict):
            alert_dict = alert
        else:
            alert_dict = {"message": str(alert), "severity": "info"}

        # Ensure timestamp
        if "ts" not in alert_dict:
            alert_dict["ts"] = datetime.now(timezone.utc).isoformat()

        successes = 0
        for ch in self._channels:
            try:
                ok = await ch.send(alert_dict)
                if ok:
                    successes += 1
                else:
                    self._stats.total_channel_failures += 1
            except Exception:
                logger.exception("Channel %s failed", type(ch).__name__)
                self._stats.total_channel_failures += 1

        self._stats.total_dispatched += 1
        return successes

    def dispatch_sync(self, alert: object) -> None:
        """Fire-and-forget dispatch from synchronous code."""
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(self.dispatch(alert))
        except RuntimeError:
            # No running event loop — run directly
            asyncio.run(self.dispatch(alert))

    def list_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: str | None = None,
        detector: str | None = None,
    ) -> list[dict]:
        return self._in_memory.list_alerts(limit, offset, severity, detector)

    def alert_count(self) -> int:
        return self._in_memory.count()

    def stats(self) -> dict:
        mem_stats = self._in_memory.stats()
        return {
            **mem_stats,
            "total_dispatched": self._stats.total_dispatched,
            "total_channel_failures": self._stats.total_channel_failures,
            "channels_registered": self._stats.channels_registered,
            "webhook_count": len(self._webhooks),
        }
