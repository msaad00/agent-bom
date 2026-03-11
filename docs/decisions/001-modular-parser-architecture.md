# ADR-001: Modular Parser Architecture

**Status:** Accepted
**Date:** 2026-03-11

## Context

The `parsers/__init__.py` module grew to 1,250+ lines containing parsers for
every supported ecosystem (npm, pip, poetry, conda, uv, yarn, pnpm, Go, Maven,
Cargo). This made the file hard to navigate, debug, and extend. Adding a new
ecosystem parser meant modifying a single massive file, increasing merge
conflict risk across contributors.

## Decision

Split parsers by ecosystem into dedicated modules:

- `parsers/python_parsers.py` — pip, poetry, uv, conda
- `parsers/node_parsers.py` — npm, yarn, pnpm, npx detection
- `parsers/compiled_parsers.py` — Go, Maven, Cargo, uvx detection
- `parsers/__init__.py` — orchestration (`extract_packages`, `scan_project_directory`),
  registry lookup, and re-exports for backward compatibility

Each module is self-contained: it imports only `models.Package` and standard
library modules. No cross-parser dependencies.

**Alternatives considered:**

1. *One file per parser function* — Too granular. 15+ tiny files would be harder
   to navigate than 3 ecosystem groups.
2. *Plugin/registry pattern* — Over-engineered for the current scale. The
   ecosystem grouping provides natural boundaries without dynamic dispatch.

## Consequences

- **Positive:** `parsers/__init__.py` reduced from 1,250 to 430 lines (-66%).
  Contributors can find and modify ecosystem-specific code instantly.
- **Positive:** Adding a new ecosystem (e.g., NuGet, Gradle) means creating one
  new file, adding a re-export, and wiring it into `extract_packages()`.
- **Positive:** Merge conflicts between parser PRs eliminated — each ecosystem
  is in its own file.
- **Trade-off:** Re-export block in `__init__.py` must be maintained. Forgetting
  a re-export breaks backward compatibility for external consumers.
- **Convention:** All parser modules export functions that take `Path` and return
  `list[Package]`. Command detectors take `MCPServer` and return `list[Package]`.
