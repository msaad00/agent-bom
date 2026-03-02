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

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol

logger = logging.getLogger(__name__)


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


class SplunkHEC:
    """Splunk HTTP Event Collector connector."""

    def __init__(self, config: SIEMConfig) -> None:
        self.config = config
        self.url = config.url.rstrip("/")

    def send_event(self, event: dict) -> bool:
        import httpx

        payload = {
            "event": event,
            "sourcetype": self.config.source_type,
            "time": time.time(),
        }
        if self.config.index:
            payload["index"] = self.config.index

        try:
            resp = httpx.post(
                f"{self.url}/services/collector/event",
                json=payload,
                headers={"Authorization": f"Splunk {self.config.token}"},
                verify=self.config.verify_ssl,
                timeout=10,
            )
            return resp.status_code == 200
        except Exception:
            logger.exception("Splunk HEC send failed")
            return False

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
        import httpx

        payload = {
            "ddsource": "agent-bom",
            "ddtags": f"source:agent-bom,type:{event.get('type', 'scan_alert')}",
            "hostname": os.environ.get("HOSTNAME", "agent-bom"),
            "message": json.dumps(event),
        }

        try:
            resp = httpx.post(
                f"{self.url}/api/v2/logs",
                json=[payload],
                headers={
                    "DD-API-KEY": self.config.token,
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            return resp.status_code in (200, 202)
        except Exception:
            logger.exception("Datadog send failed")
            return False

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
        import httpx

        doc = {
            **event,
            "@timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "agent-bom",
        }
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.config.token:
            headers["Authorization"] = f"Bearer {self.config.token}"

        try:
            resp = httpx.post(
                f"{self.url}/{self.index}/_doc",
                json=doc,
                headers=headers,
                verify=self.config.verify_ssl,
                timeout=10,
            )
            return resp.status_code in (200, 201)
        except Exception:
            logger.exception("Elasticsearch send failed")
            return False

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
    )
    return create_connector(siem_type, config)
