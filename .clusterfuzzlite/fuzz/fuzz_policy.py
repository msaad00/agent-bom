"""Atheris fuzz target for agent-bom policy engine.

Fuzzes two attack surfaces:
1. evaluate_expression() — custom expression parser accepting arbitrary strings
2. _validate_policy() — JSON policy structure validation

These are the highest-value targets because they accept untrusted user input
(policy files, condition expressions) and involve custom parsing logic.
"""

import sys

import atheris

with atheris.instrument_imports():
    from agent_bom.policy import _validate_policy, evaluate_expression


def _make_fake_blast_radius(fdp):
    """Build a minimal BlastRadius-like object from fuzz data."""

    class _FakeBR:
        severity = fdp.PickValueInList(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"])
        cvss_score = fdp.ConsumeFloat()
        epss_score = fdp.ConsumeFloat()
        has_credentials = fdp.ConsumeBool()
        credential_count = fdp.ConsumeIntInRange(0, 50)
        package_count = fdp.ConsumeIntInRange(0, 200)
        agent_count = fdp.ConsumeIntInRange(0, 20)
        server_count = fdp.ConsumeIntInRange(0, 50)
        is_kev = fdp.ConsumeBool()
        is_exploited = fdp.ConsumeBool()
        cve_id = fdp.ConsumeUnicodeNoSurrogates(20)

    return _FakeBR()


def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    choice = fdp.ConsumeIntInRange(0, 1)

    if choice == 0:
        # Fuzz the expression evaluator with arbitrary expression strings
        expr = fdp.ConsumeUnicodeNoSurrogates(256)
        br = _make_fake_blast_radius(fdp)
        try:
            evaluate_expression(expr, br)
        except (ValueError, TypeError, AttributeError, RecursionError, ZeroDivisionError):
            pass

    else:
        # Fuzz the policy structure validator with arbitrary dict shapes
        import json

        raw = fdp.ConsumeUnicodeNoSurrogates(1024)
        try:
            data_obj = json.loads(raw)
            if isinstance(data_obj, dict):
                _validate_policy(data_obj)
        except (json.JSONDecodeError, ValueError, TypeError, KeyError):
            pass


def main():
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
