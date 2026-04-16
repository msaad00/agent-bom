"""Atheris fuzz target for external scanner JSON ingestion.

Fuzzes:
1. detect_and_parse() — auto-detect external scanner JSON format
2. parse_trivy_json() — Trivy findings ingestion
3. parse_grype_json() — Grype findings ingestion
4. parse_syft_json() — Syft inventory ingestion

These parsers accept customer-supplied JSON exports and must reject malformed
input safely without crashes, runaway recursion, or unsafe assumptions about
shape.
"""

from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from agent_bom.parsers.external_scanners import (
        detect_and_parse,
        parse_grype_json,
        parse_syft_json,
        parse_trivy_json,
    )


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 3)
    raw = fdp.ConsumeUnicodeNoSurrogates(4096)

    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
        return

    if not isinstance(obj, dict):
        return

    try:
        if choice == 0:
            detect_and_parse(obj)
        elif choice == 1:
            parse_trivy_json(obj)
        elif choice == 2:
            parse_grype_json(obj)
        else:
            parse_syft_json(obj)
    except (ValueError, TypeError, KeyError, AttributeError, IndexError):
        pass


def main() -> None:
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
