# agent-bom Contracts

This directory contains versioned integration contracts for downstream
dashboards, SIEM pipelines, evidence exports, and procurement review.

The current stable family is [`v1`](./v1/README.md). v1 contracts are additive:
new optional fields may be added in minor releases, but required fields and
field meanings must not be removed or repurposed without a v2 contract.
