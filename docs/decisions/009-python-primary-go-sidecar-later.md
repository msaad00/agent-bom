# ADR-009: Python-Primary Runtime; Optional Go Sidecar Later

**Status:** Accepted
**Date:** 2026-07-23

## Context

Dogfood deployments and scale discussions keep surfacing the same tension:
Go’s concurrency model is attractive for long-lived network daemons (high
connection fanout, cheap goroutines, predictable memory under load), while
shipping two full product stacks (Python edition vs Go edition) would double
maintenance across scanners, cloud connectors, API contracts, CLI, MCP tools,
docs, and release artifacts.

We already have a Go tree under `sdks/go`, and operators sometimes assume that
implies a second runtime engine. We need a clear product boundary so
contributors do not fork the architecture prematurely, and so scale work stays
evidence-driven rather than language-fashion-driven.

ADR-004 already chose a Python stdio/HTTP proxy path for runtime enforcement.
That choice stands until measurement shows a hot path that Python cannot meet
under a stable control-plane contract.

## Decision

**One product. Python-primary today. Optional Go worker/sidecar later — only
for proven hot paths.**

1. **Primary runtime** remains Python for scanners, cloud connectors, FastAPI
   control plane, MCP server, CLI, and proxy/gateway as shipped today.
2. **Optional Go sidecar/worker** may be introduced later only where profilers
   and production load prove a hot path — for example high-concurrency gateway
   relay or long-lived collectors — behind a **stable HTTP/gRPC contract** owned
   by the Python control plane.
3. **`sdks/go` remains a CLIENT SDK** for calling the control-plane API. It is
   not a second product runtime and must not grow into a parallel scanner/API
   engine without a new ADR.

**Non-goals**

- No “Python edition” vs “Go edition” of agent-bom.
- No wholesale rewrite of cloud connectors (or the scan path) into Go without
  profiler evidence and an explicit ADR update.
- No requirement that scan, CLI, or MCP paths depend on a Go binary today.

**Relates to:** [ADR-004](004-proxy-runtime-enforcement.md) — proxy/runtime
enforcement stays Python until measured need justifies an optional sidecar for
a specific hot path under the same policy/audit contract.

## Consequences

- **Orchestration stays Python.** Job scheduling, auth, RBAC, tenant scope,
  graph writes, and policy remain in the control plane; any future Go process is
  a worker the control plane starts and supervises.
- **Release shape unchanged for now.** Primary artifacts remain the Python
  wheel (and Docker images built from it) plus the Next.js UI. A future Go
  sidecar would be an *additional* optional artifact, not a replacement edition.
- **Contract-first if/when Go lands.** Sidecar I/O must be covered by contract
  tests (HTTP/gRPC schemas, fail-open/fail-closed behavior, audit relay) so the
  Python plane can swap or roll back without dual product semantics.
- **Positive:** Contributors have a clear default — extend Python — and a
  narrow, evidence-gated path for Go where concurrency truly matters.
- **Negative:** Some network-daemon workloads may hit Python concurrency limits
  before a sidecar exists; mitigate with horizontal workers and measurement
  rather than speculative rewrites.
