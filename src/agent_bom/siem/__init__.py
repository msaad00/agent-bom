"""SIEM connectors — forward alerts and scan results to external systems.

Supported targets:
    - Splunk (HEC — HTTP Event Collector)
    - Datadog (Log API)
    - Elasticsearch / OpenSearch
    - Syslog (RFC 5424 over TCP/TLS with OCSF formatting)

Each connector implements the SIEMConnector protocol and is registered
in the _CONNECTORS dict for dynamic dispatch.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger(__name__)


def _delivery_identity(kind: str, url: str, index: str) -> str:
    material = json.dumps([kind, url, index], separators=(",", ":"), ensure_ascii=True)
    return f"siem-{kind}-{hashlib.sha256(material.encode('utf-8')).hexdigest()[:16]}"


def _event_identity(kind: str, destination_id: str, event: dict[str, Any]) -> str:
    material = json.dumps(
        {"destination_id": destination_id, "event": event, "kind": kind},
        sort_keys=True,
        separators=(",", ":"),
        default=str,
        ensure_ascii=True,
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _deliver_event(
    *,
    kind: str,
    config: "SIEMConfig",
    url: str,
    payload: dict[str, Any] | list[dict[str, Any]],
    source_event: dict[str, Any],
    auth_scheme: str,
    auth_header: str,
    auth_token: str,
    accepted_statuses: frozenset[int],
) -> bool:
    """Send one SIEM payload through the governed delivery foundation."""

    from agent_bom.delivery import Delivery, Destination, get_delivery_client
    from agent_bom.security import sanitize_error, sanitize_text

    destination_id = _delivery_identity(kind, url, config.index)
    destination = Destination(
        destination_id=destination_id,
        url=url,
        kind=f"siem.{kind}",
        auth_scheme=auth_scheme,
        auth_header=auth_header,
        auth_token=auth_token,
        headers={"Content-Type": "application/json"},
        accepted_statuses=accepted_statuses,
        allow_private_networks=config.allow_private_networks,
        timeout=10.0,
    )
    delivery = Delivery(
        destination_id=destination_id,
        payload=payload,
        event_type=f"siem.{kind}",
        idempotency_key=_event_identity(kind, destination_id, source_event),
    )
    try:
        return get_delivery_client().deliver(destination, delivery).delivered
    except Exception as exc:  # noqa: BLE001 - preserve connector boolean contract
        safe = sanitize_error(exc, generic=True)
        logger.warning("SIEM delivery setup failed for %s: %s", kind, sanitize_text(safe))
        return False


class SIEMConnector(Protocol):
    """Protocol for SIEM integrations."""

    def send_event(self, event: dict) -> bool: ...
    def send_batch(self, events: list[dict]) -> int: ...
    def health_check(self) -> bool: ...


@dataclass
class SIEMConfig:
    """Configuration for a SIEM connector."""

    name: str
    url: str
    token: str = ""
    index: str = ""
    source_type: str = "agent-bom"
    verify_ssl: bool = True
    event_format: str = "raw"
    allow_private_networks: bool = False


class SplunkHEC:
    """Splunk HTTP Event Collector connector."""

    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self.url = config.url.rstrip("/")

    def send_event(self, event: dict) -> bool:
        payload = {
            "event": event,
            "sourcetype": self.config.source_type,
            "time": time.time(),
        }
        if self.config.index:
            payload["index"] = self.config.index

        return _deliver_event(
            kind="splunk",
            config=self.config,
            url=f"{self.url}/services/collector/event",
            payload=payload,
            source_event=event,
            auth_scheme="header",
            auth_header="Authorization",
            auth_token=f"Splunk {self.config.token}",
            accepted_statuses=frozenset({200}),
        )

    def send_batch(self, events: list[dict]) -> int:
        return sum(1 for e in events if self.send_event(e))

    def health_check(self) -> bool:
        import httpx

        try:
            resp = httpx.get(
                f"{self.url}/services/collector/health/1.0",
                headers={"Authorization": f"Splunk {self.config.token}"},
                verify=self.config.verify_ssl,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False


class DatadogLogs:
    """Datadog Log API connector."""

    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self.url = config.url or "https://http-intake.logs.datadoghq.com"

    def send_event(self, event: dict) -> bool:
        payload = {
            "ddsource": "agent-bom",
            "ddtags": f"source:agent-bom,type:{event.get('type', 'scan_alert')}",
            "hostname": os.environ.get("HOSTNAME", "agent-bom"),
            "message": json.dumps(event),
        }

        return _deliver_event(
            kind="datadog",
            config=self.config,
            url=f"{self.url}/api/v2/logs",
            payload=[payload],
            source_event=event,
            auth_scheme="header",
            auth_header="DD-API-KEY",
            auth_token=self.config.token,
            accepted_statuses=frozenset({200, 202}),
        )

    def send_batch(self, events: list[dict]) -> int:
        return sum(1 for e in events if self.send_event(e))

    def health_check(self) -> bool:
        import httpx

        try:
            resp = httpx.get(
                "https://api.datadoghq.com/api/v1/validate",
                headers={"DD-API-KEY": self.config.token},
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False


class ElasticsearchConnector:
    """Elasticsearch / OpenSearch connector."""

    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self.url = config.url.rstrip("/")
        self.index = config.index or "agent-bom-alerts"

    def send_event(self, event: dict) -> bool:
        doc = {
            **event,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "agent-bom",
        }
        return _deliver_event(
            kind="elasticsearch",
            config=self.config,
            url=f"{self.url}/{self.index}/_doc",
            payload=doc,
            source_event=event,
            auth_scheme="bearer" if self.config.token else "",
            auth_header="Authorization",
            auth_token=self.config.token,
            accepted_statuses=frozenset({200, 201}),
        )

    def send_batch(self, events: list[dict]) -> int:
        return sum(1 for e in events if self.send_event(e))

    def health_check(self) -> bool:
        import httpx

        headers: dict[str, str] = {}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"
        try:
            resp = httpx.get(
                f"{self.url}/_cluster/health",
                headers=headers,
                verify=self.config.verify_ssl,
                timeout=5,
            )
            return resp.status_code == 200
        except Exception:
            return False


# ── Registry ────────────────────────────────────────────────────────


def _lazy_syslog():
    from agent_bom.siem.ocsf import SyslogConnector

    return SyslogConnector


_CONNECTORS: dict[str, type] = {
    "splunk": SplunkHEC,
    "datadog": DatadogLogs,
    "elasticsearch": ElasticsearchConnector,
    "opensearch": ElasticsearchConnector,
}


def create_connector(name: str, config: SIEMConfig) -> SIEMConnector:
    """Create a SIEM connector by name."""
    if name == "syslog":
        cls = _lazy_syslog()
        return cls(config)
    cls = _CONNECTORS.get(name)
    if cls is None:
        available = sorted(list(_CONNECTORS) + ["syslog"])
        raise ValueError(f"Unknown SIEM connector: {name!r}. Available: {available}")
    return cls(config)


def list_connectors() -> list[str]:
    return sorted(list(_CONNECTORS.keys()) + ["syslog"])


def format_event(event: dict, fmt: str = "raw") -> dict:
    """Format an alert event for SIEM export.

    Args:
        event: The raw alert dict.
        fmt: ``"raw"`` for passthrough, ``"ocsf"`` for OCSF Detection Finding.
    """
    if fmt == "ocsf":
        from agent_bom.siem.ocsf import to_ocsf_detection_finding

        return to_ocsf_detection_finding(event)
    return event


def list_formats() -> list[str]:
    """Return supported SIEM event formats."""
    return ["raw", "ocsf"]


def create_from_env() -> SIEMConnector | None:
    """Auto-configure SIEM from environment variables.

    Env vars:
        AGENT_BOM_SIEM_TYPE: splunk|datadog|elasticsearch
        AGENT_BOM_SIEM_URL: endpoint URL
        AGENT_BOM_SIEM_TOKEN: auth token
        AGENT_BOM_SIEM_INDEX: index/sourcetype (optional)
    """
    siem_type = os.environ.get("AGENT_BOM_SIEM_TYPE", "")
    if not siem_type:
        return None

    config = SIEMConfig(
        name=siem_type,
        url=os.environ.get("AGENT_BOM_SIEM_URL", ""),
        token=os.environ.get("AGENT_BOM_SIEM_TOKEN", ""),
        index=os.environ.get("AGENT_BOM_SIEM_INDEX", ""),
        allow_private_networks=os.environ.get("AGENT_BOM_ALLOW_PRIVATE_EGRESS_URLS", "").strip().lower()
        in {"1", "true", "yes", "on"},
    )
    return create_connector(siem_type, config)
