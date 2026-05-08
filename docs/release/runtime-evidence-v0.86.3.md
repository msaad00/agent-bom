# Runtime Evidence Pack: v0.86.3

Generated artifact: [`runtime-evidence-v0.86.3.json`](runtime-evidence-v0.86.3.json)

Regenerate before release:

```bash
uv run python scripts/generate_runtime_evidence_pack.py \
  --docker-smoke \
  --output docs/release/runtime-evidence-v0.86.3.json
```

This evidence pack covers:

- gateway `/healthz`
- incoming bearer-token enforcement
- policy-blocked gateway tool call
- gateway Prometheus metrics
- upstream bearer-token header resolution from an environment variable
- gateway transport boundary: streamable-http request/response only; persistent
  SSE and stdio relay stay on per-MCP proxy wrappers
- proxy sandbox posture: read-only rootfs, `--network none`, `--cap-drop ALL`,
  `no-new-privileges`, CPU/memory/PID/tmpfs limits, digest-pinned image evidence
- proxy audit hash-chain verification
- runtime Docker image smoke for `agent-bom proxy`

The Docker smoke intentionally uses `--no-isolate` because it runs the proxy
inside the runtime image and does not assume nested Docker access. Sandbox
isolation evidence is generated separately from the same sandbox command builder
used by the proxy.
