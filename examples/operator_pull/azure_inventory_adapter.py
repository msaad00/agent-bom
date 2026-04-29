#!/usr/bin/env python3
"""Emit canonical agent-bom inventory from Azure inside the operator boundary."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent))

from inventory_writer import DISCOVERY_METHODS, build_inventory_payload  # noqa: E402

from agent_bom.cloud.azure import discover  # noqa: E402
from agent_bom.security import sanitize_security_warnings  # noqa: E402


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Emit Azure discovery as canonical agent-bom inventory JSON.")
    parser.add_argument("--subscription-id", help="Azure subscription ID. Defaults to AZURE_SUBSCRIPTION_ID.")
    parser.add_argument("--resource-group", help="Optional Azure resource group scope.")
    parser.add_argument("--output", "-o", default="-", help="Output path, or '-' for stdout.")
    parser.add_argument("--compact", action="store_true", help="Emit compact JSON.")
    parser.add_argument("--source", default="azure-operator-pull", help="Inventory source label.")
    parser.add_argument(
        "--discovery-method",
        choices=sorted(DISCOVERY_METHODS),
        default="operator_pushed_inventory",
        help="How this inventory was collected before agent-bom ingestion.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    agents, warnings = discover(
        subscription_id=args.subscription_id,
        resource_group=args.resource_group,
    )
    for warning in sanitize_security_warnings(warnings):
        sys.stderr.write(f"warning: {warning}\n")

    payload = build_inventory_payload(
        agents,
        provider_name="azure",
        source=args.source,
        collector="examples/operator_pull/azure_inventory_adapter.py",
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
