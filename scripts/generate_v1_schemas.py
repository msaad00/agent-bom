#!/usr/bin/env python3
"""Generate JSON Schema (draft 2020-12) for every Pydantic model in
``agent_bom.api.models`` and write them under ``docs/schemas/v1/``.

Closes #1963. SDK consumers and downstream platform integrations need a
stable contract surface they can codegen against; the Pydantic models
already are the source of truth, so the cleanest contract is the
JSON Schema they emit. The committed schemas are the published artifact
and ``--check`` mode asserts that every regen matches them so an
unintended model edit cannot ship without updating the contract.

Usage:

    python scripts/generate_v1_schemas.py            # write fresh schemas
    python scripts/generate_v1_schemas.py --check    # CI drift gate

The generator is intentionally side-effect-free: it imports the models
module, walks every public Pydantic class, and serialises the schema
into a per-model file. No network, no I/O beyond ``docs/schemas/v1/``.
"""

from __future__ import annotations

import argparse
import inspect
import json
import sys
from pathlib import Path

from pydantic import BaseModel

import agent_bom.api.models as models_module

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "docs" / "schemas" / "v1"
INDEX_FILE = SCHEMA_DIR / "index.json"


# Models reachable from `agent_bom.api.models`. Filter to classes
# defined in that module (skip imported BaseModel re-exports) and only
# proper Pydantic models.
def _public_models() -> list[type[BaseModel]]:
    out: list[type[BaseModel]] = []
    for name, obj in vars(models_module).items():
        if name.startswith("_"):
            continue
        if not inspect.isclass(obj):
            continue
        if not issubclass(obj, BaseModel) or obj is BaseModel:
            continue
        # Only the models defined in this module — skip transitive imports
        # like `from pydantic import BaseModel` and any re-exports from
        # other internal modules (we want the v1 surface to be one file).
        if obj.__module__ != models_module.__name__:
            continue
        out.append(obj)
    return sorted(out, key=lambda cls: cls.__name__)


def _schema_payload(cls: type[BaseModel]) -> dict[str, object]:
    return cls.model_json_schema(mode="serialization")


def _write_schema(cls: type[BaseModel]) -> tuple[Path, str]:
    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    payload = _schema_payload(cls)
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    path = SCHEMA_DIR / f"{cls.__name__}.json"
    return path, rendered


def _write_index(classes: list[type[BaseModel]]) -> tuple[Path, str]:
    payload = {
        "version": "v1",
        "generator": "scripts/generate_v1_schemas.py",
        "source_module": models_module.__name__,
        "models": [
            {
                "name": cls.__name__,
                "schema": f"{cls.__name__}.json",
                "doc": (cls.__doc__ or "").strip().splitlines()[0] if cls.__doc__ else "",
            }
            for cls in classes
        ],
    }
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    return INDEX_FILE, rendered


def _diff_message(path: Path, expected: str) -> str | None:
    if not path.exists():
        return f"missing: {path.relative_to(ROOT)}"
    actual = path.read_text(encoding="utf-8")
    if actual != expected:
        return f"drift: {path.relative_to(ROOT)} differs from generated output"
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when committed schemas diverge from generated output. CI gate.",
    )
    args = parser.parse_args()

    classes = _public_models()
    if not classes:
        print("ERROR: no Pydantic models found in agent_bom.api.models", file=sys.stderr)
        return 1

    pending: list[tuple[Path, str]] = []
    for cls in classes:
        pending.append(_write_schema(cls))
    pending.append(_write_index(classes))

    if args.check:
        problems: list[str] = []
        for path, content in pending:
            problem = _diff_message(path, content)
            if problem is not None:
                problems.append(problem)
        # Also catch deletions: every committed file must correspond to a
        # generated entry, otherwise a model rename would leave a stale
        # schema sitting in the published surface.
        expected_paths = {path for path, _ in pending}
        if SCHEMA_DIR.exists():
            for existing in SCHEMA_DIR.iterdir():
                if existing.is_file() and existing not in expected_paths:
                    problems.append(f"stale: {existing.relative_to(ROOT)} no longer matches a model")
        if problems:
            print("docs/schemas/v1/ is out of sync with agent_bom.api.models:", file=sys.stderr)
            for problem in problems:
                print(f"  - {problem}", file=sys.stderr)
            print(
                "Run `python scripts/generate_v1_schemas.py` to refresh the contracts.",
                file=sys.stderr,
            )
            return 1
        print(f"OK: docs/schemas/v1/ matches {len(classes)} models in agent_bom.api.models")
        return 0

    SCHEMA_DIR.mkdir(parents=True, exist_ok=True)
    written = 0
    for path, content in pending:
        if not path.exists() or path.read_text(encoding="utf-8") != content:
            path.write_text(content, encoding="utf-8")
            written += 1
    print(f"Wrote {written} schema file(s) under docs/schemas/v1/ ({len(classes)} models total).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
