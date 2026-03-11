# Architecture Decision Records (ADRs)

This directory contains Architecture Decision Records (ADRs) that document
key technical decisions made in agent-bom. ADRs help contributors understand
**why** the codebase is structured the way it is — not just what the code does.

## Format

Each ADR follows this structure:

- **Title**: Short, descriptive name
- **Status**: Accepted / Superseded / Deprecated
- **Context**: What problem or question led to this decision
- **Decision**: What we chose and why
- **Consequences**: Trade-offs, what changes as a result

## Index

| # | Title | Status | Date |
|---|-------|--------|------|
| 001 | [Modular Parser Architecture](001-modular-parser-architecture.md) | Accepted | 2026-03-11 |
| 002 | [OSV-First Vulnerability Strategy](002-osv-first-vuln-strategy.md) | Accepted | 2026-03-11 |
| 003 | [FastAPI APIRouter Pattern](003-fastapi-apirouter-pattern.md) | Accepted | 2026-03-11 |
| 004 | [Proxy-Based Runtime Enforcement](004-proxy-runtime-enforcement.md) | Accepted | 2026-03-11 |
| 005 | [Re-Export Pattern for Backward Compatibility](005-re-export-pattern.md) | Accepted | 2026-03-11 |

## Adding a New ADR

1. Copy the template: `cp docs/decisions/_template.md docs/decisions/NNN-title.md`
2. Fill in the sections
3. Add it to the index above
4. Submit a PR
