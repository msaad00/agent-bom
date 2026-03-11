# ADR-003: FastAPI APIRouter Pattern for Route Modules

**Status:** Accepted
**Date:** 2026-03-11

## Context

The `api/server.py` module grew to 3,127 lines containing 84 route handlers
across 17 domain groups (scan, compliance, fleet, gateway, proxy, governance,
enterprise, etc.). This monolithic structure made it difficult to:

- Navigate to a specific endpoint's implementation
- Understand which routes belong to which domain
- Modify one domain without risking merge conflicts in another
- Test routes in isolation

## Decision

Extract route handlers into domain-specific modules under `api/routes/` using
FastAPI's `APIRouter`. Each module defines a `router = APIRouter()` with its
routes, and `server.py` includes them via `app.include_router(router)`.

**Module structure:**

```
api/
├── server.py          # App creation, lifespan, middleware, router includes
├── models.py          # Request/response Pydantic models
├── middleware.py       # Auth, rate limiting, body size middleware
├── stores.py          # Store globals and thread-safe accessors
├── pipeline.py        # Scan orchestration pipeline
└── routes/
    ├── __init__.py
    ├── compliance.py   # /v1/compliance, /v1/posture/*
    ├── fleet.py        # /v1/fleet/*
    ├── gateway.py      # /v1/gateway/*
    ├── proxy.py        # /v1/proxy/*, /ws/proxy/*
    └── ...             # One module per domain
```

**Alternatives considered:**

1. *Blueprint/namespace pattern* — Not native to FastAPI. APIRouter is the
   idiomatic FastAPI solution and provides the same functionality.
2. *Class-based views* — Adds OOP complexity without clear benefit. FastAPI's
   function-based routes are simpler and more testable.
3. *Separate FastAPI sub-applications* — Overkill. Sub-apps have separate
   middleware stacks and OpenAPI schemas, which would fragment the API docs.

## Consequences

- **Positive:** Each domain is independently navigable, testable, and
  modifiable. Contributors find endpoints by domain, not by scrolling.
- **Positive:** Merge conflicts between route PRs eliminated — each domain
  is in its own file. server.py only changes when adding a new router include.
- **Positive:** OpenAPI documentation remains unified — all routes appear in
  a single `/docs` page with proper tag grouping.
- **Trade-off:** `server.py` must import and include each router. This is a
  single line per domain module — minimal maintenance burden.
- **Convention:** Every route module exports `router = APIRouter()`. Routes
  use full paths (e.g., `/v1/compliance`) rather than prefix-based routing,
  keeping URLs explicit and grep-friendly.
