#!/usr/bin/env python3
"""Prepare private graph evidence and measure a reviewed investigation workflow."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_bom.graph.investigation_measurement import (  # noqa: E402
    InvestigationReview,
    Snapshot,
    evaluate_investigation,
    evidence_digest,
)

MAX_INPUT_BYTES = 32 * 1024 * 1024


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError("non-finite JSON value")


def _read(path: Path) -> dict[str, Any]:
    with path.open("rb") as stream:
        raw = stream.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("input exceeds byte budget")
    data = json.loads(raw, object_pairs_hook=_object, parse_constant=_reject_constant)
    if not isinstance(data, dict):
        raise ValueError("expected JSON object")
    return data


def _write(path: Path, data: dict[str, Any]) -> None:
    # Serialize before creating the artifact; O_EXCL preserves existing evidence.
    encoded = json.dumps(data, sort_keys=True, indent=2, allow_nan=False) + "\n"
    with path.open("x") as stream:
        stream.write(encoded)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare", help="Wrap an unmodified canonical graph export with collector metadata")
    prepare.add_argument("--graph", type=Path, required=True)
    prepare.add_argument("--scope-id", required=True)
    prepare.add_argument("--collected-at", required=True)
    prepare.add_argument("--source-evidence-ref", required=True)
    prepare.add_argument(
        "--collection-complete", action="store_true", help="Declare complete source collection, only with collector evidence"
    )
    prepare.add_argument("--output", type=Path, required=True)
    measure = commands.add_parser("measure", help="Evaluate privately reviewed before/after evidence")
    for name in ("before", "after", "review", "output"):
        measure.add_argument("--" + name, type=Path, required=True)
    schema = commands.add_parser("review-schema", help="Write the strict operator review JSON schema")
    schema.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            payload = {
                "scope_id": args.scope_id,
                "collected_at": args.collected_at,
                "source_evidence_ref": args.source_evidence_ref,
                "collection_complete": args.collection_complete,
                "graph": _read(args.graph),
            }
            Snapshot.model_validate(payload)
            _write(args.output, payload)
            print(evidence_digest(payload))
        elif args.command == "review-schema":
            _write(args.output, InvestigationReview.model_json_schema())
            print("Review schema written.")
        else:
            payload = evaluate_investigation(_read(args.before), _read(args.after), _read(args.review))
            _write(args.output, payload)
            print("Measurement written. Operator-reviewed evidence; independent verification not established.")
    except (OSError, ValueError, TypeError, RecursionError):
        # Validation errors can echo customer source values and filesystem paths.
        print(
            "Evidence evaluation failed: check JSON/schema, scope, digests, chronology, input size and a new output path.", file=sys.stderr
        )
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
