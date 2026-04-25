"""Release scanner accuracy evidence helpers."""

from __future__ import annotations

from typing import Any

from agent_bom.red_team import run_red_team

_SCHEMA_VERSION = "accuracy-baseline/v1"


def build_accuracy_baseline() -> dict[str, Any]:
    """Build a deterministic scanner accuracy evidence summary."""
    red_team = run_red_team()
    return {
        "schema_version": _SCHEMA_VERSION,
        "scope": {
            "release_gate": True,
            "claims": [
                "runtime detector false-positive/false-negative accounting",
                "demo inventory advisory realism",
                "VEX and fixed-verified findings tracked separately from active unresolved risk",
            ],
            "non_claims": [
                "published real-world FP/FN rate across customer repositories",
                "graph reachability precision for every framework and dynamic import path",
            ],
        },
        "runtime_red_team": {
            "total_cases": red_team["total"],
            "attack_cases": red_team["attacks"],
            "benign_cases": red_team["benign"],
            "detected_attacks": red_team["detected"],
            "missed_attacks": red_team["missed"],
            "false_positives": red_team["false_positives"],
            "detection_rate": red_team["detection_rate"],
            "false_positive_rate": red_team["false_positive_rate"],
            "by_category": red_team["by_category"],
        },
        "scanner_corpus": {
            "demo_inventory": {
                "guardrail": "tests/test_demo_inventory_accuracy.py",
                "guarantee": (
                    "Every vulnerable demo package resolves to at least one bundled advisory, "
                    "with explicitly allowed clean packages separated."
                ),
            },
            "known_vulnerable_network_corpus": {
                "guardrail": "tests/test_accuracy_baseline.py",
                "mode": "network",
                "guarantee": "Known vulnerable package versions must resolve through live OSV when network regression tests are enabled.",
            },
            "parser_identity_contracts": {
                "guardrail": "tests/test_discovery_new_clients.py and parser-dedup tests",
                "guarantee": "Known equivalent package identities collapse while intentional non-merges remain separate.",
            },
        },
        "finding_state_accounting": {
            "active_unresolved": "Counts toward posture, policy gates, MCP scan gates, and release summaries.",
            "vex_suppressed": "Tracked separately when VEX marks a vulnerability as fixed or not_affected.",
            "fixed_verified": "Tracked separately through tenant finding feedback controls.",
            "accepted_risk": "Tracked separately through tenant finding feedback controls.",
            "false_positive": (
                "Tracked separately through tenant finding feedback controls and excluded from low-FP claims unless evidence exists."
            ),
        },
        "release_validation": [
            "uv run pytest tests/test_red_team.py -q",
            "uv run pytest tests/test_demo_inventory_accuracy.py -q",
            "uv run pytest tests/test_accuracy_baseline.py -q -m network",
            "uv run python scripts/generate_accuracy_baseline.py --check",
        ],
    }
