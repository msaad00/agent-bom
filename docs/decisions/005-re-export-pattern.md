# ADR-005: Re-Export Pattern for Backward Compatibility

**Status:** Accepted
**Date:** 2026-03-11

## Context

When extracting functions from monolithic modules (e.g., `parsers/__init__.py`,
`discovery/__init__.py`) into submodules, existing code throughout the codebase
imports from the original module path:

```python
from agent_bom.parsers import parse_npm_packages
from agent_bom.discovery import parse_mcp_config
```

Changing all import sites in a single PR would create massive diffs, increase
merge conflict risk, and make the refactoring PR harder to review.

## Decision

Use **re-exports** in the original `__init__.py` to maintain backward
compatibility after extraction:

```python
# Re-export Node.js parsers for backward compatibility
from agent_bom.parsers.node_parsers import (  # noqa: F401
    parse_npm_packages,
    parse_yarn_lock,
    ...
)
```

The `# noqa: F401` suppresses ruff's "imported but unused" warning, since
the imports exist solely for re-export.

**Rules:**

1. Every extracted function MUST be re-exported from the original module
2. Re-exports are grouped by source module with a comment header
3. No import site changes in the extraction PR — re-exports handle it
4. Import sites MAY be updated in future PRs to use direct imports, but
   this is not required

**Alternatives considered:**

1. *Update all import sites in the same PR* — Creates huge diffs (50+ files),
   high conflict risk, and hard to review. Violates our <300 lines per PR rule.
2. *Deprecation warnings* — Overkill for internal refactoring. We're not a
   library with external consumers on PyPI.
3. *`__getattr__` lazy loading* — More complex, harder to understand, and
   breaks IDE autocompletion. Re-exports are explicit and grep-friendly.

## Consequences

- **Positive:** Extraction PRs are small and focused — only the source module
  and new submodule change. No import sites need updating.
- **Positive:** Zero breaking changes. All existing code continues to work.
- **Positive:** IDE autocompletion and type checking work correctly since
  re-exports are explicit import statements.
- **Trade-off:** `__init__.py` files accumulate re-export blocks. This is
  acceptable — the blocks are clearly commented and easy to maintain.
- **Trade-off:** Slight import overhead from the indirection. Negligible for
  module-level imports (loaded once at startup).
