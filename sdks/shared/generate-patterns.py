#!/usr/bin/env python3
"""Generate patterns.json from the canonical Python patterns.py source.

This ensures TypeScript and Go SDKs use identical detection patterns.
Run with --check to verify patterns.json is up-to-date (used in CI).

Usage:
    python sdks/shared/generate-patterns.py           # generate
    python sdks/shared/generate-patterns.py --check   # CI verification
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PATTERNS_PY = ROOT / "src" / "agent_bom" / "runtime" / "patterns.py"
OUTPUT = Path(__file__).resolve().parent / "patterns.json"


def _flags_str(pattern: re.Pattern) -> str:
    """Convert re flags to portable string representation."""
    parts: list[str] = []
    if pattern.flags & re.IGNORECASE:
        parts.append("i")
    if pattern.flags & re.MULTILINE:
        parts.append("m")
    return "".join(parts)


def _serialize_pair(name: str, pattern: re.Pattern) -> dict:
    return {"name": name, "pattern": pattern.pattern, "flags": _flags_str(pattern)}


def _serialize_triple(name: str, pattern: re.Pattern, weight: float) -> dict:
    return {"name": name, "pattern": pattern.pattern, "flags": _flags_str(pattern), "weight": weight}


def _serialize_sequence(name: str, steps: list[str], description: str) -> dict:
    return {"name": name, "steps": steps, "description": description}


def generate() -> dict:
    # Import the canonical patterns module
    sys.path.insert(0, str(ROOT / "src"))
    from agent_bom.runtime.patterns import (
        CORTEX_MODEL_PATTERNS,
        CREDENTIAL_PATTERNS,
        DANGEROUS_ARG_PATTERNS,
        RESPONSE_BASE64_PATTERN,
        RESPONSE_CLOAKING_PATTERNS,
        RESPONSE_INJECTION_PATTERNS,
        RESPONSE_INVISIBLE_CHARS,
        RESPONSE_SVG_PATTERNS,
        SEMANTIC_INJECTION_SIGNALS,
        SUSPICIOUS_SEQUENCES,
    )

    return {
        "_comment": "Auto-generated from src/agent_bom/runtime/patterns.py — do not edit manually",
        "credential_patterns": [_serialize_pair(n, p) for n, p in CREDENTIAL_PATTERNS],
        "dangerous_arg_patterns": [_serialize_pair(n, p) for n, p in DANGEROUS_ARG_PATTERNS],
        "cortex_model_patterns": [_serialize_pair(n, p) for n, p in CORTEX_MODEL_PATTERNS],
        "response_cloaking_patterns": [_serialize_pair(n, p) for n, p in RESPONSE_CLOAKING_PATTERNS],
        "response_svg_patterns": [_serialize_pair(n, p) for n, p in RESPONSE_SVG_PATTERNS],
        "response_invisible_chars": [_serialize_pair(n, p) for n, p in RESPONSE_INVISIBLE_CHARS],
        "response_base64_pattern": {
            "pattern": RESPONSE_BASE64_PATTERN.pattern,
            "flags": _flags_str(RESPONSE_BASE64_PATTERN),
        },
        "response_injection_patterns": [_serialize_pair(n, p) for n, p in RESPONSE_INJECTION_PATTERNS],
        "suspicious_sequences": [_serialize_sequence(n, s, d) for n, s, d in SUSPICIOUS_SEQUENCES],
        "semantic_injection_signals": [_serialize_triple(n, p, w) for n, p, w in SEMANTIC_INJECTION_SIGNALS],
        "thresholds": {
            "semantic_injection_suspicious": 0.4,
            "semantic_injection_high": 0.7,
            "rate_limit_default_threshold": 50,
            "rate_limit_default_window_seconds": 60,
            "max_message_bytes": 10485760,
            "client_readline_timeout_seconds": 120,
            "replay_window_seconds": 300,
            "replay_max_entries": 10000,
        },
    }


def main() -> None:
    data = generate()
    current = json.dumps(data, indent=2, ensure_ascii=False) + "\n"

    if "--check" in sys.argv:
        if not OUTPUT.exists():
            print(f"FAIL: {OUTPUT} does not exist — run: python {__file__}")
            sys.exit(1)
        existing = OUTPUT.read_text()
        if existing != current:
            print(f"FAIL: {OUTPUT} is stale — regenerate with: python {__file__}")
            sys.exit(1)
        print(f"OK: {OUTPUT} is up-to-date")
        return

    OUTPUT.write_text(current)
    print(
        f"Generated {OUTPUT} ({len(data['credential_patterns'])} credential, "
        f"{len(data['dangerous_arg_patterns'])} arg, "
        f"{len(data['response_injection_patterns'])} injection, "
        f"{len(data['semantic_injection_signals'])} semantic patterns)"
    )


if __name__ == "__main__":
    main()
