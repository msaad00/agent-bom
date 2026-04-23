# Visual Leak Detection

The visual leak detector is the OCR-backed response safety layer for screenshot
and image-heavy MCP tools. It is intentionally opt-in because it adds OCR
dependencies and CPU cost to the runtime path.

Use this guide when you want to understand:

- when OCR inspection actually runs
- what the detector scans and redacts
- how proxy and gateway startup behave
- how to roll it out without creating avoidable false positives or latency

## What it inspects

The detector only runs on MCP response content blocks that look like image
payloads:

- `result.content[]`
- `type: "image"`
- base64-encoded `data`
- `mimeType` such as `image/png` or `image/jpeg`

It does not OCR arbitrary text responses, prompt bodies, or request payloads.
Those stay on the normal runtime detector path.

The OCR pass joins all image blocks in a single response into one stitched
canvas, extracts words above the current confidence floor, and matches them
against the shipped credential and PII pattern sets.

Current boundary:

- this is response-image OCR and redaction, not universal screenshot governance
- it only runs where `proxy` or `gateway` are actually deployed
- it is not yet a default-on redaction layer for every screenshot-heavy runtime path

Current matching behavior:

- single-word and short multi-word matches
- OCR confidence floor: `40`
- categories: `credential_leak` and `pii_leak`
- redaction shape: opaque black rectangles over matched bounding boxes

## Runtime contract

The detector needs both:

- `agent-bom[visual]`
- a working `tesseract` binary on `PATH`

If either is missing, the runtime is considered unavailable.

## Proxy behavior

Enable it on the proxy path with:

```bash
agent-bom proxy \
  --control-plane-url https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_API_TOKEN" \
  --detect-visual-leaks \
  -- npx @modelcontextprotocol/server-playwright
```

Proxy startup behavior is strict:

- if `--detect-visual-leaks` is set, proxy startup requires the OCR runtime
- there is no best-effort startup flag on the proxy path
- timeouts during response inspection fail open and let the original response
  continue

Response-path behavior:

- if no leak is found, the response passes through unchanged
- if a leak is found, alerts are logged and the image content is redacted before
  the client sees it
- response HMAC signing happens before redaction so the audit trail still pins
  the original server response

## Gateway behavior

Enable it on the gateway path with:

```bash
agent-bom gateway serve \
  --from-control-plane https://agent-bom.internal.example.com \
  --control-plane-token "$AGENT_BOM_CONTROL_PLANE_TOKEN" \
  --detect-visual-leaks
```

Gateway startup gives you two modes:

- required: `--detect-visual-leaks`
- best effort: `--detect-visual-leaks --allow-visual-leak-best-effort`

Required mode fails startup if OCR support is unavailable. Best-effort mode
keeps the gateway up and reports the missing runtime through `/healthz`.

Example readiness check:

```bash
curl -s http://gateway.agent-bom.svc.cluster.local:8090/healthz | jq .visual_leak_detection
```

Expected shape:

```json
{
  "enabled": true,
  "ready": true,
  "mode": "enforcing",
  "reason": null,
  "required": true
}
```

Like the proxy path, gateway response inspection fails open on OCR timeout. The
response is still returned, and the timeout is logged instead of blocking tool
traffic.

## Where it helps most

The detector is most useful for:

- browser automation MCPs
- screenshot or screen-read tools
- visual review or QA MCPs
- any tool that returns image evidence from customer environments

It is much less useful for:

- text-only MCPs
- stdio wrappers around file or git tools
- workflows where screenshots are disabled entirely

## False-positive and latency posture

This detector is designed to be useful, not magical.

Operationally important limits:

- OCR quality depends on image quality and font rendering
- small text, blurred screenshots, and heavily compressed images reduce recall
- high-noise screenshots may still cause matches on credential-like patterns
- the detector only sees pixels, not semantic page context

Recommended rollout:

1. Start on a narrow set of screenshot-heavy tools.
2. Turn it on first in non-critical user groups or review environments.
3. Watch response latency and the `gateway.visual_leak_blocked` /
   proxy-side audit events before widening coverage.
4. Use required mode only after validating that your runtime image actually
   includes `tesseract`.

## Recommended deployment shapes

| Surface | Recommended mode | Why |
|---|---|---|
| Developer laptop proxy | required only after package validation | laptops are sensitive to startup surprises |
| EKS sidecar proxy | required | image contents are fully operator-controlled |
| Shared gateway pilot | best effort first | easier to validate OCR packaging and latency |
| Shared gateway production | required | fail closed only after runtime support is proven |

## What is real now vs still narrower

Shipped now:

- OCR-backed response inspection on image content blocks
- credential and PII leak detection categories
- proxy and gateway startup/readiness behavior
- redaction of matched bounding boxes before the response reaches the client

Still intentionally narrower:

- always-on screenshot redaction across every deployment mode
- request-side OCR inspection
- a claim that visual redaction is already the default runtime posture everywhere

That is why the feature stays opt-in and rollout-first in this release.

## Related guides

- [Runtime Monitoring](runtime-monitoring.md)
- [Endpoint Fleet](endpoint-fleet.md)
- [Your Own AWS / EKS](own-infra-eks.md)
- [Packaged API + UI Control Plane](control-plane-helm.md)
