# Architecture Decision Records

This directory contains the original Architecture Decision Records (ADRs) for
agent-bom. New ADRs live in [`docs/decisions`](../decisions/README.md), which
is the canonical decision log for current work.

ADRs document significant technical decisions — the context, options considered,
and rationale for the chosen approach. They help current and future contributors
understand *why* the codebase is shaped the way it is.

## Format

We use [MADR](https://adr.github.io/madr/) (Markdown Any Decision Records).

## Index

| ADR | Title | Status | Date |
|-----|-------|--------|------|
| [001](001-osv-primary-vuln-source.md) | OSV as primary vulnerability source | Accepted | 2025-06 |
| [002](002-custom-policy-engine.md) | Custom JSON policy engine over OPA | Accepted | 2025-08 |
| [003](003-cyclonedx-sbom-format.md) | CycloneDX as primary SBOM format | Accepted | 2025-07 |
| [004](004-subprocess-over-sdk.md) | Subprocess CLI over vendor SDKs | Accepted | 2025-06 |
| [005](005-no-rbac-custom-auth.md) | API auth without RBAC framework | Accepted | 2025-11 |

## Adding a new ADR

1. Use `docs/decisions/_template.md`
2. Add the new record under `docs/decisions/`
3. Add it to the `docs/decisions/README.md` index
4. Submit as part of your PR
