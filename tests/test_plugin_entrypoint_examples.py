"""Contract tests for documented plugin entry-point examples."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples" / "plugin_entrypoints"


def _load_example(name: str) -> ModuleType:
    path = EXAMPLES / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeMcp:
    def __init__(self) -> None:
        self.tools: dict[str, Any] = {}

    def tool(self, *, title: str):
        def decorator(func):
            self.tools[func.__name__] = {"title": title, "func": func}
            return func

        return decorator


def test_mcp_tool_example_registers_read_only_tool() -> None:
    module = _load_example("example_mcp_tools")

    registration = module.registration()
    assert registration.name == "example-posture-tool"
    assert registration.register_attr == "register_tools"
    assert registration.capabilities.writes is False
    assert registration.capabilities.data_boundary == "metadata_only_example"

    fake_mcp = FakeMcp()
    module.register_tools(fake_mcp)
    payload = json.loads(fake_mcp.tools["example_asset_posture"]["func"](asset_id="workstation-1"))
    assert payload == {
        "asset_id": "workstation-1",
        "data_boundary": "metadata_only_example",
        "status": "observed",
        "writes": False,
    }


def test_advisory_source_example_declares_license_and_source_url() -> None:
    module = _load_example("example_advisory_source")

    registration = module.registration()
    assert registration.name == "example-advisory-source"
    assert registration.lookup_attr == "lookup"
    assert registration.sync_attr == "sync"
    assert registration.capabilities.network_access is True
    assert registration.capabilities.data_boundary == "operator_owned_advisory_metadata"

    advisory = module.lookup("CVE-2026-0001")
    assert advisory["id"] == "CVE-2026-0001"
    assert advisory["license"] == "link-only"
    assert advisory["redistribution"] == "summary_only"
    assert advisory["source_url"].endswith("/CVE-2026-0001")

    sync = module.sync(since="2026-05-22T00:00:00+00:00")
    assert sync["license"] == "link-only"
    assert sync["items_seen"] == 0


def test_runtime_emitter_example_buffers_redacted_metadata_only_events() -> None:
    module = _load_example("example_runtime_emitter")

    registration = module.registration()
    assert registration.name == "example-runtime-emitter"
    assert registration.emit_attr == "emit"
    assert registration.flush_attr == "flush"
    assert registration.capabilities.writes is True
    assert "no_prompt_bodies" in registration.capabilities.guarantees

    queued = module.emit(
        {
            "tenant_id": "tenant-alpha",
            "source_agent": "security-reviewer",
            "tool": "query",
            "decision": "blocked",
            "arguments": {"secret": "not retained"},
        }
    )
    assert queued["queued"] is True
    assert queued["buffered"] == 1

    flushed = module.flush()
    assert flushed == {"flushed": 1}
