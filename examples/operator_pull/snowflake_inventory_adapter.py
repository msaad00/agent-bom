#!/usr/bin/env python3
"""Emit canonical agent-bom inventory from Snowflake inside the operator boundary.

This adapter runs with the operator's Snowflake auth context and writes
canonical inventory JSON locally. Passing that inventory to agent-bom is an
explicit handoff, so agent-bom does not need Snowflake credentials for the
scan/graph/export workflow.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from adapter_bootstrap import add_repo_src_to_path, exit_for_missing_agent_bom  # noqa: E402

add_repo_src_to_path(__file__)

from inventory_writer import DISCOVERY_METHODS, build_inventory_payload  # noqa: E402

try:
    from agent_bom.cloud.snowflake import discover  # noqa: E402
    from agent_bom.security import sanitize_error, sanitize_security_warnings  # noqa: E402
except ModuleNotFoundError as exc:
    exit_for_missing_agent_bom(exc)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit Snowflake discovery as canonical agent-bom inventory JSON.")
    parser.add_argument("--account", help="Snowflake account identifier. Defaults to SNOWFLAKE_ACCOUNT.")
    parser.add_argument("--user", help="Snowflake user. Defaults to SNOWFLAKE_USER.")
    parser.add_argument(
        "--authenticator",
        help="Snowflake authenticator such as externalbrowser, snowflake_jwt, or oauth.",
    )
    parser.add_argument("--database", help="Optional Snowflake database scope.")
    parser.add_argument("--schema", help="Optional Snowflake schema scope.")
    parser.add_argument("--output", "-o", default="-", help="Output path, or '-' for stdout.")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON.")
    parser.add_argument("--source", default="snowflake-operator-pull", help="Inventory source label.")
    parser.add_argument(
        "--discovery-method",
        choices=sorted(DISCOVERY_METHODS),
        default="operator_pushed_inventory",
        help="How this inventory was collected before agent-bom ingestion.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        agents, warnings = discover(
            account=args.account,
            user=args.user,
            authenticator=args.authenticator,
            database=args.database,
            schema=args.schema,
        )
    except Exception as exc:  # noqa: BLE001
        safe_error = sanitize_error(exc) or exc.__class__.__name__
        sys.stderr.write(f"error: Snowflake discovery failed: {safe_error}\n")
        return 2
    for warning in sanitize_security_warnings(warnings):
        sys.stderr.write(f"warning: {warning}\n")

    payload = build_inventory_payload(
        agents,
        provider_name="snowflake",
        source=args.source,
        collector="examples/operator_pull/snowflake_inventory_adapter.py",
        discovery_method=args.discovery_method,
    )
    text = json.dumps(payload, indent=None if args.compact else 2, sort_keys=True) + "\n"
    if args.output == "-":
        sys.stdout.write(text)
    else:
        Path(args.output).write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
