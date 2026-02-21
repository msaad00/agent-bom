"""Config watch + alerting — monitor MCP config files for changes and alert on new risks.

Uses filesystem watchers to continuously monitor MCP client configuration files.
On change, re-scans the affected config, diffs against the last scan, and sends
alerts if new risks are introduced.

Requires: pip install 'agent-bom[watch]'  (for watchdog dependency)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

logger = logging.getLogger(__name__)


# ─── Alert model ─────────────────────────────────────────────────────────────


@dataclass
class Alert:
    """A security alert triggered by a config change."""

    timestamp: str = ""
    alert_type: str = ""  # new_server, new_vulnerability, credential_added, config_changed
    severity: str = "info"  # critical, high, medium, low, info
    summary: str = ""
    details: dict = field(default_factory=dict)
    config_path: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()


# ─── Alert sinks ─────────────────────────────────────────────────────────────


class AlertSink(Protocol):
    """Protocol for alert delivery."""

    def send(self, alert: Alert) -> None: ...


class ConsoleAlertSink:
    """Print alerts to the console using rich."""

    def send(self, alert: Alert) -> None:
        from rich.console import Console

        con = Console(stderr=True)
        severity_styles = {
            "critical": "red bold",
            "high": "red",
            "medium": "yellow",
            "low": "dim",
            "info": "cyan",
        }
        style = severity_styles.get(alert.severity, "white")
        con.print(
            f"  [{style}][{alert.severity.upper()}][/{style}] "
            f"{alert.summary}"
        )
        if alert.details:
            for key, val in alert.details.items():
                con.print(f"    [dim]{key}: {val}[/dim]")


class WebhookAlertSink:
    """POST alerts to a webhook URL (Slack, Teams, PagerDuty, etc.)."""

    def __init__(self, url: str):
        self.url = url

    def send(self, alert: Alert) -> None:
        import httpx

        payload = {
            "text": f"[{alert.severity.upper()}] {alert.summary}",
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "config_path": alert.config_path,
            "details": alert.details,
            "timestamp": alert.timestamp,
        }
        try:
            httpx.post(self.url, json=payload, timeout=10.0)
        except Exception:  # noqa: BLE001
            logger.warning("Failed to send webhook alert to %s", self.url)


class FileAlertSink:
    """Append alerts to a JSONL file."""

    def __init__(self, path: str):
        self.path = path

    def send(self, alert: Alert) -> None:
        with open(self.path, "a") as f:
            f.write(json.dumps(asdict(alert)) + "\n")


# ─── Config watcher ──────────────────────────────────────────────────────────


def discover_config_paths() -> list[Path]:
    """Discover all known MCP config file paths that exist on this system."""
    from agent_bom.discovery import CONFIG_LOCATIONS, expand_path, get_platform

    platform = get_platform()
    paths: list[Path] = []

    for _agent_type, platforms in CONFIG_LOCATIONS.items():
        for p in platforms.get(platform, []):
            expanded = expand_path(p)
            if expanded.exists():
                paths.append(expanded)

    return paths


def discover_config_dirs() -> list[Path]:
    """Get unique parent directories of all discovered config files."""
    paths = discover_config_paths()
    return list({p.parent for p in paths})


class ConfigChangeHandler:
    """Filesystem event handler that triggers scans on config changes."""

    def __init__(
        self,
        alert_sinks: list[AlertSink],
        debounce_seconds: float = 2.0,
    ):
        self.alert_sinks = alert_sinks
        self.debounce_seconds = debounce_seconds
        self._last_trigger: dict[str, float] = {}
        self._last_scan: Optional[dict] = None

    def on_modified(self, path: str) -> None:
        """Handle a file modification event."""
        now = time.time()
        last = self._last_trigger.get(path, 0)
        if now - last < self.debounce_seconds:
            return  # Debounce

        self._last_trigger[path] = now
        logger.info("Config change detected: %s", path)
        self._scan_and_alert(path)

    def _scan_and_alert(self, config_path: str) -> None:
        """Re-scan the changed config and diff against last scan."""
        try:
            from agent_bom.discovery import discover_all
            from agent_bom.models import AIBOMReport
            from agent_bom.output import to_json
            from agent_bom.parsers import extract_packages

            # Discover and scan
            agents = discover_all()
            for agent in agents:
                for server in agent.mcp_servers:
                    server.packages = extract_packages(server)

            report = AIBOMReport(agents=agents)
            current_scan = to_json(report)

            # Diff
            if self._last_scan:
                from agent_bom.history import diff_reports
                diff = diff_reports(self._last_scan, current_scan)
                self._process_diff(diff, config_path)
            else:
                # First scan — just report what we found
                alert = Alert(
                    alert_type="config_changed",
                    severity="info",
                    summary=f"Initial scan: {report.total_agents} agent(s), {report.total_servers} server(s)",
                    config_path=config_path,
                )
                self._send_alert(alert)

            self._last_scan = current_scan

        except Exception as exc:  # noqa: BLE001
            logger.error("Scan failed after config change: %s", exc)

    def _process_diff(self, diff: dict, config_path: str) -> None:
        """Generate alerts from a scan diff."""
        summary = diff.get("summary", {})

        new_findings = summary.get("new_findings", 0)
        new_packages = summary.get("new_packages", 0)

        if new_findings > 0:
            # Determine max severity of new findings
            max_sev = "low"
            for finding in diff.get("new", []):
                sev = finding.get("severity", "").lower()
                if sev == "critical":
                    max_sev = "critical"
                    break
                elif sev == "high" and max_sev != "critical":
                    max_sev = "high"
                elif sev == "medium" and max_sev not in ("critical", "high"):
                    max_sev = "medium"

            alert = Alert(
                alert_type="new_vulnerability",
                severity=max_sev,
                summary=f"{new_findings} new vulnerability/ies detected after config change",
                details={
                    "new_findings": new_findings,
                    "resolved_findings": summary.get("resolved_findings", 0),
                },
                config_path=config_path,
            )
            self._send_alert(alert)

        if new_packages > 0:
            alert = Alert(
                alert_type="config_changed",
                severity="info",
                summary=f"{new_packages} new package(s) added",
                config_path=config_path,
            )
            self._send_alert(alert)

    def _send_alert(self, alert: Alert) -> None:
        """Send alert to all configured sinks."""
        for sink in self.alert_sinks:
            try:
                sink.send(alert)
            except Exception:  # noqa: BLE001
                logger.warning("Alert sink failed: %s", type(sink).__name__)


def start_watching(
    alert_sinks: list[AlertSink],
    debounce_seconds: float = 2.0,
) -> None:
    """Start watching MCP config files for changes.

    Blocks indefinitely until KeyboardInterrupt.
    Requires watchdog: pip install 'agent-bom[watch]'
    """
    try:
        from watchdog.events import FileSystemEventHandler
        from watchdog.observers import Observer
    except ImportError:
        raise ImportError(
            "watchdog is required for `agent-bom watch`.\n"
            "Install with: pip install 'agent-bom[watch]'"
        ) from None

    handler = ConfigChangeHandler(alert_sinks, debounce_seconds)

    class _WatchdogHandler(FileSystemEventHandler):
        def on_modified(self, event):
            if not event.is_directory:
                handler.on_modified(event.src_path)

    config_dirs = discover_config_dirs()
    if not config_dirs:
        logger.warning("No MCP config directories found to watch")
        return

    observer = Observer()
    watchdog_handler = _WatchdogHandler()

    for config_dir in config_dirs:
        observer.schedule(watchdog_handler, str(config_dir), recursive=False)
        logger.info("Watching: %s", config_dir)

    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
