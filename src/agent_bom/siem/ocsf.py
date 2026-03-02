"""OCSF v1.1 Detection Finding format + RFC 5424 syslog transport.

Converts agent-bom alerts and scan findings into the Open Cybersecurity
Schema Framework (OCSF) Detection Finding format (class_uid 2004) for
standardised SIEM integration.

Includes a ``SyslogConnector`` that delivers OCSF-formatted events over
TCP/TLS following RFC 5424.
"""

from __future__ import annotations

import json
import logging
import os
import socket
import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OCSF severity mapping
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, int] = {
    "critical": 5,  # Fatal
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,  # Informational
}

_SEVERITY_NAMES: dict[int, str] = {v: k.title() for k, v in _SEVERITY_MAP.items()}


# ---------------------------------------------------------------------------
# OCSF Detection Finding formatter
# ---------------------------------------------------------------------------


def to_ocsf_detection_finding(
    alert: dict[str, Any],
    product_version: str = "0.0.0",
) -> dict[str, Any]:
    """Convert an agent-bom alert dict to OCSF Detection Finding (class_uid 2004).

    Follows OCSF v1.1.0 schema.  The ``alert`` dict is expected to have at
    minimum ``severity`` and ``message`` keys (the standard runtime alert
    shape produced by ``runtime.detectors.Alert.to_dict()``).
    """
    severity_str = str(alert.get("severity", "medium")).lower()
    severity_id = _SEVERITY_MAP.get(severity_str, 3)

    details = alert.get("details", {})
    detector = alert.get("detector", alert.get("type", "unknown"))
    rule_id = details.get("rule_id", str(uuid4()))
    message = alert.get("message", "Detection finding")

    return {
        # Activity
        "activity_id": 1,
        "activity_name": "Create",
        # Category
        "category_uid": 2,
        "category_name": "Findings",
        # Class
        "class_uid": 2004,
        "class_name": "Detection Finding",
        # Type (class_uid * 100 + activity_id)
        "type_uid": 200401,
        "type_name": "Detection Finding: Create",
        # Severity
        "severity_id": severity_id,
        "severity": _SEVERITY_NAMES.get(severity_id, "Medium"),
        # Timing
        "time": int(time.time() * 1000),
        # Finding
        "finding_info": {
            "title": message,
            "desc": details.get("description", message),
            "types": [detector],
            "uid": rule_id,
        },
        # Evidence
        "evidences": [{"data": json.dumps(details)}] if details else [],
        # Metadata
        "metadata": {
            "product": {
                "name": "agent-bom",
                "vendor_name": "msaad00",
                "version": product_version,
            },
            "version": "1.1.0",
            "log_name": "agent-bom-detection",
        },
        # Status
        "status_id": 1,  # New
    }


def to_ocsf_batch(
    alerts: list[dict[str, Any]],
    product_version: str = "0.0.0",
) -> list[dict[str, Any]]:
    """Convert a batch of alerts to OCSF Detection Finding format."""
    return [to_ocsf_detection_finding(a, product_version) for a in alerts]


# ---------------------------------------------------------------------------
# RFC 5424 syslog formatting
# ---------------------------------------------------------------------------

# Syslog facility: 1 = user-level
_FACILITY = 1

# OCSF severity → syslog severity (RFC 5424 §6.2.1)
_SYSLOG_SEVERITY: dict[int, int] = {
    5: 2,  # Critical → Critical
    4: 3,  # High → Error
    3: 4,  # Medium → Warning
    2: 5,  # Low → Notice
    1: 6,  # Info → Informational
}


def _format_rfc5424(
    facility: int,
    severity: int,
    app_name: str,
    msg: str,
    hostname: str | None = None,
) -> str:
    """Format a message as RFC 5424 syslog.

    Returns a string in the format::

        <PRI>1 TIMESTAMP HOSTNAME APP-NAME - - - MSG
    """
    pri = facility * 8 + severity
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    host = hostname or socket.gethostname()
    return f"<{pri}>1 {ts} {host} {app_name} - - - {msg}"


# ---------------------------------------------------------------------------
# Syslog connector
# ---------------------------------------------------------------------------


@dataclass
class _SyslogConfig:
    host: str
    port: int
    use_tls: bool


def _parse_host_port(url: str) -> tuple[str, int]:
    """Extract host and port from a syslog URL.

    Supports ``syslog://host:port``, ``host:port``, or bare ``host``
    (defaults to port 514).
    """
    url = url.replace("syslog://", "").replace("tcp://", "").rstrip("/")
    if ":" in url:
        host, port_str = url.rsplit(":", 1)
        return host, int(port_str)
    return url, 514


class SyslogConnector:
    """RFC 5424 syslog over TCP with optional TLS."""

    def __init__(self, config: Any) -> None:
        """Accept a ``SIEMConfig`` (from ``siem/__init__.py``)."""
        host, port = _parse_host_port(config.url)
        self.host = host
        self.port = port
        self.use_tls = getattr(config, "verify_ssl", True)
        self.app_name = "agent-bom"
        self._product_version = os.environ.get("AGENT_BOM_VERSION", "0.0.0")

    def send_event(self, event: dict) -> bool:
        """Convert event to OCSF, format as RFC 5424, send over TCP."""
        try:
            ocsf = to_ocsf_detection_finding(event, self._product_version)
            severity_id = ocsf.get("severity_id", 3)
            syslog_sev = _SYSLOG_SEVERITY.get(severity_id, 4)
            msg = _format_rfc5424(_FACILITY, syslog_sev, self.app_name, json.dumps(ocsf))
            return self._send_tcp(msg)
        except Exception:
            logger.exception("Syslog send failed")
            return False

    def send_batch(self, events: list[dict]) -> int:
        """Send a batch of events, returns count of successful sends."""
        return sum(1 for e in events if self.send_event(e))

    def health_check(self) -> bool:
        """Test TCP connectivity to the syslog server."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=5)
            sock.close()
            return True
        except Exception:
            return False

    def _send_tcp(self, msg: str) -> bool:
        """Send a single RFC 5424 message over TCP (optionally TLS)."""
        try:
            sock = socket.create_connection((self.host, self.port), timeout=10)
            if self.use_tls:
                ctx = ssl.create_default_context()
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            # RFC 5425: octet-counting framing
            payload = msg.encode("utf-8")
            frame = f"{len(payload)} ".encode("utf-8") + payload
            sock.sendall(frame)
            sock.close()
            return True
        except Exception:
            logger.exception("Syslog TCP send failed to %s:%d", self.host, self.port)
            return False
