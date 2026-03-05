"""Tests for centralized logging configuration."""

import json
import logging
import os
import tempfile

from agent_bom.logging_config import ConsoleFormatter, JSONFormatter, setup_logging


class TestJSONFormatter:
    def test_basic_format(self):
        formatter = JSONFormatter()
        record = logging.LogRecord(
            name="agent_bom.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert parsed["level"] == "INFO"
        assert parsed["logger"] == "agent_bom.test"
        assert parsed["msg"] == "test message"
        assert "ts" in parsed

    def test_exception_format(self):
        formatter = JSONFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
        record = logging.LogRecord(
            name="agent_bom.test",
            level=logging.ERROR,
            pathname="test.py",
            lineno=1,
            msg="error occurred",
            args=(),
            exc_info=exc_info,
        )
        output = formatter.format(record)
        parsed = json.loads(output)
        assert "exception" in parsed
        assert "ValueError" in parsed["exception"]


class TestConsoleFormatter:
    def test_format_has_level(self):
        formatter = ConsoleFormatter(fmt="%(levelname)s %(message)s")
        record = logging.LogRecord(name="test", level=logging.WARNING, pathname="", lineno=0, msg="warn", args=(), exc_info=None)
        output = formatter.format(record)
        assert "warn" in output


class TestSetupLogging:
    def setup_method(self):
        """Reset agent_bom logger before each test."""
        root = logging.getLogger("agent_bom")
        root.handlers.clear()
        root.setLevel(logging.WARNING)

    def test_default_level(self):
        # Remove env var if set
        env_backup = os.environ.pop("AGENT_BOM_LOG_LEVEL", None)
        try:
            setup_logging()
            root = logging.getLogger("agent_bom")
            assert root.level == logging.WARNING
        finally:
            if env_backup:
                os.environ["AGENT_BOM_LOG_LEVEL"] = env_backup

    def test_debug_level(self):
        setup_logging(level="DEBUG")
        root = logging.getLogger("agent_bom")
        assert root.level == logging.DEBUG

    def test_env_level(self, monkeypatch):
        monkeypatch.setenv("AGENT_BOM_LOG_LEVEL", "ERROR")
        setup_logging()
        root = logging.getLogger("agent_bom")
        assert root.level == logging.ERROR

    def test_json_output(self):
        setup_logging(level="INFO", json_output=True)
        root = logging.getLogger("agent_bom")
        assert len(root.handlers) == 1
        assert isinstance(root.handlers[0].formatter, JSONFormatter)

    def test_file_handler(self):
        with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as f:
            path = f.name
        try:
            setup_logging(level="DEBUG", log_file=path)
            logger = logging.getLogger("agent_bom.test_file")
            logger.info("file log test")
            root = logging.getLogger("agent_bom")
            # Should have stderr + file handler
            assert len(root.handlers) == 2
            # Flush and check file
            for h in root.handlers:
                h.flush()
            with open(path) as f:
                content = f.read()
            assert "file log test" in content
            parsed = json.loads(content.strip())
            assert parsed["msg"] == "file log test"
        finally:
            os.unlink(path)

    def test_no_duplicate_handlers(self):
        """Calling setup_logging twice should not duplicate handlers."""
        setup_logging(level="INFO")
        setup_logging(level="DEBUG")
        root = logging.getLogger("agent_bom")
        assert len(root.handlers) == 1

    def test_noisy_loggers_quieted(self):
        setup_logging(level="DEBUG")
        assert logging.getLogger("httpx").level >= logging.WARNING
        assert logging.getLogger("httpcore").level >= logging.WARNING
