#!/usr/bin/env python3
"""Export MCP schemas from an isolated, exact published release installation.

The hosted origin may run newer code while retaining a release version string.
It must not define the expected marketplace contract. Child processes receive
no publishing credentials, user pip configuration, or checkout import path.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

EXTRACT = """
import asyncio, json, sys
from importlib.metadata import version
from agent_bom import __version__
from agent_bom.mcp_server import create_mcp_server
expected = sys.argv[1]
if version('agent-bom') != expected or __version__ != expected:
    raise SystemExit('Installed release version mismatch')
tools = asyncio.run(create_mcp_server(profile='scan').list_tools())
print(json.dumps(sorted([{'name': t.name, 'inputSchema': t.inputSchema} for t in tools], key=lambda t: t['name'])))
"""


def export_contract(expected: str, names: list[str]) -> list[dict]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", expected):
        raise ValueError("Expected release must be a stable version")
    if not names or any(not isinstance(name, str) or not name for name in names) or len(names) != len(set(names)):
        raise ValueError("Expected release tool names must be unique non-empty strings")
    with tempfile.TemporaryDirectory(prefix="agent-bom-release-contract-") as directory:
        root = Path(directory)
        env = {"PATH": os.defpath, "HOME": str(root), "LANG": "C.UTF-8"}
        if "SYSTEMROOT" in os.environ:
            env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]

        def run(command: list[str], timeout: int) -> subprocess.CompletedProcess[str]:
            return subprocess.run(command, cwd=root, env=env, text=True, capture_output=True, check=True, timeout=timeout)

        run([sys.executable, "-I", "-m", "venv", str(root / "venv")], 60)
        python = str(root / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python"))
        run(
            [
                python,
                "-I",
                "-m",
                "pip",
                "--isolated",
                "--disable-pip-version-check",
                "install",
                "--index-url",
                "https://pypi.org/simple",
                "--only-binary=:all:",
                f"agent-bom=={expected}",
            ],
            300,
        )
        result = run([python, "-I", "-c", EXTRACT, expected], 60)
        contract = json.loads(result.stdout)
    if not isinstance(contract, list) or any(
        not isinstance(tool, dict) or not isinstance(tool.get("inputSchema"), dict) for tool in contract
    ):
        raise ValueError("Published release returned malformed tool schemas")
    if [tool.get("name") for tool in contract] != sorted(names):
        raise ValueError("Published release tools differ from immutable release metadata")
    return contract


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected", required=True)
    parser.add_argument("--expected-tool-names-file", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        names = json.loads(args.expected_tool_names_file.read_text())
        if not isinstance(names, list):
            raise ValueError("Expected tool names must be a list")
        contract = export_contract(args.expected, names)
    except (OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("Could not export exact published release schemas; no hosted-origin fallback is permitted") from None
    args.out.write_text(json.dumps(contract, indent=2, sort_keys=True) + "\n")
    print(f"Exported {len(contract)} MCP tool schemas from published agent-bom=={args.expected}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
