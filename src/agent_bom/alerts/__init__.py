"""Alert pipeline — route runtime and scan alerts to configured channels."""

from agent_bom.alerts.dispatcher import (
    AlertDispatcher,
    InMemoryChannel,
    SlackChannel,
    WebhookChannel,
)
from agent_bom.alerts.scan_alerts import alerts_from_scan_result

__all__ = [
    "AlertDispatcher",
    "InMemoryChannel",
    "SlackChannel",
    "WebhookChannel",
    "alerts_from_scan_result",
]
