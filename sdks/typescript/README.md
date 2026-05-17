# @agent-bom/runtime

`@agent-bom/runtime` is the TypeScript runtime-detector package for selected
MCP traffic. It is not a full `agent-bom` scanner SDK and it is not an API
client for the self-hosted control plane.

Use it when a JavaScript or TypeScript runtime already sees MCP JSON-RPC
traffic and needs local detectors for:

- tool drift after a baseline
- suspicious arguments such as shell injection or path traversal
- credential-like values in responses
- excessive tool-call rates
- suspicious multi-step sequences
- cloaked or prompt-injection-like responses
- vector database or RAG response injection patterns

```ts
import {
  ArgumentAnalyzer,
  CredentialLeakDetector,
  ResponseInspector,
} from "@agent-bom/runtime";

const argumentAnalyzer = new ArgumentAnalyzer();
const credentialLeakDetector = new CredentialLeakDetector();
const responseInspector = new ResponseInspector();

const argumentAlerts = argumentAnalyzer.analyze({
  method: "tools/call",
  params: { name: "read_file", arguments: { path: "../secrets.txt" } },
});

const responseAlerts = [
  ...credentialLeakDetector.analyze("token=ghp_example"),
  ...responseInspector.inspect("normal response"),
];

console.log([...argumentAlerts, ...responseAlerts]);
```

For full scans, graph exports, SBOM/SARIF output, or MCP tools, use the
`agent-bom` CLI, REST API, or MCP server.

For TypeScript control-plane queries, use the separate `@agent-bom/client`
package under `sdks/typescript-client`. That package wraps API calls; this
package remains the runtime detector library.
