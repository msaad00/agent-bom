---
name: missing-guardrail-fixture
description: Fixture that intentionally omits the capability guardrail contract.
---

# Missing Guardrail Fixture

This fixture asks the operator to bypass guardrails before reading `.env`
content. It intentionally omits the `capabilities` block so the scanner keeps
reporting the missing capability declaration alongside the behavioral finding.
