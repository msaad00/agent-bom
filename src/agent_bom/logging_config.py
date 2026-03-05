"""Centralized logging configuration for agent-bom.

Usage in any module:
    import logging
    logger = logging.getLogger(__name__)  # already standard

CLI / entrypoint:
    from agent_bom.logging_config import setup_logging
    setup_logging(level="DEBUG", json_output=True)

Environment variables:
    AGENT_BOM_LOG_LEVEL  — DEBUG, INFO, WARNING, ERROR (default: WARNING)
    AGENT_BOM_LOG_JSON   — 1 to enable JSON structured output
    AGENT_BOM_LOG_FILE   — path to write log file (in addition to stderr)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional


class JSONFormatter(logging.Formatter):
    """Structured JSON log formatter for production / SIEM ingestion."""

    def format(self, record: logging.LogRecord) -> str:
        entry = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info and record.exc_info[0]:
            entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "context"):
            entry["context"] = record.context
        return json.dumps(entry, default=str)


class ConsoleFormatter(logging.Formatter):
    """Human-readable colored formatter for terminal output."""

    COLORS = {
        "DEBUG": "\033[36m",  # cyan
        "INFO": "\033[32m",  # green
        "WARNING": "\033[33m",  # yellow
        "ERROR": "\033[31m",  # red
        "CRITICAL": "\033[1;31m",  # bold red
    }
    RESET = "\033[0m"

    def format(self, record: logging.LogRecord) -> str:
        color = self.COLORS.get(record.levelname, "")
        reset = self.RESET if color else ""
        record.levelname = f"{color}{record.levelname:<8}{reset}"
        return super().format(record)


def setup_logging(
    level: Optional[str] = None,
    json_output: Optional[bool] = None,
    log_file: Optional[str] = None,
) -> None:
    """Configure logging for all agent-bom modules.

    Args:
        level: Log level (DEBUG/INFO/WARNING/ERROR). Falls back to
            AGENT_BOM_LOG_LEVEL env var, then WARNING.
        json_output: Use JSON structured format. Falls back to
            AGENT_BOM_LOG_JSON env var.
        log_file: Path to log file. Falls back to AGENT_BOM_LOG_FILE env var.
    """
    level = level or os.environ.get("AGENT_BOM_LOG_LEVEL", "WARNING")
    if json_output is None:
        json_output = os.environ.get("AGENT_BOM_LOG_JSON", "").strip() in ("1", "true")
    log_file = log_file or os.environ.get("AGENT_BOM_LOG_FILE")

    root = logging.getLogger("agent_bom")
    root.setLevel(getattr(logging, level.upper(), logging.WARNING))

    # Remove existing handlers to avoid duplicates on re-init
    root.handlers.clear()

    # Stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    if json_output:
        stderr_handler.setFormatter(JSONFormatter())
    else:
        fmt = "%(asctime)s %(levelname)s %(name)s: %(message)s"
        datefmt = "%H:%M:%S"
        if sys.stderr.isatty():
            stderr_handler.setFormatter(ConsoleFormatter(fmt=fmt, datefmt=datefmt))
        else:
            stderr_handler.setFormatter(logging.Formatter(fmt=fmt, datefmt=datefmt))
    root.addHandler(stderr_handler)

    # File handler (optional)
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(JSONFormatter())
        root.addHandler(file_handler)

    # Quiet noisy third-party loggers
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)
