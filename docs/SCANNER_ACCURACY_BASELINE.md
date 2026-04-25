# Scanner Accuracy Baseline

This file defines what `agent-bom` can prove before a release and what remains a roadmap item.

The machine-readable release artifact is [`accuracy-baseline.json`](accuracy-baseline.json). It is generated with:

```bash
uv run python scripts/generate_accuracy_baseline.py
uv run python scripts/generate_accuracy_baseline.py --check
```

## Release Gate

The current release baseline covers:

- runtime red-team detector false-positive and false-negative accounting
- demo inventory advisory realism, so screenshots and examples do not claim fabricated CVEs
- VEX-suppressed and fixed-verified findings tracked separately from active unresolved risk
- known-vulnerable package regression checks when network tests are enabled

It does not claim a customer-wide real-world FP/FN rate yet. That requires a published quarterly corpus and sampled production-style repositories.

## Required Checks

```bash
uv run pytest tests/test_red_team.py -q
uv run pytest tests/test_demo_inventory_accuracy.py -q
uv run pytest tests/test_accuracy_baseline.py -q -m network
uv run python scripts/generate_accuracy_baseline.py --check
```

## Interpreting States

`active_unresolved` findings count toward posture and policy gates.

`vex_suppressed`, `fixed_verified`, `accepted_risk`, and `false_positive` are evidence states. They must remain visible in audit trails and release evidence, but they should not inflate active-risk counts.
