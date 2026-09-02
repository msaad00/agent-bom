# Reference evidence lab

This credential-free lab executes the real project dependency parser, bundled
pinned-advisory scanner, CycloneDX loader, Kubernetes IaC scanner, MCP parser,
and a strict local identity-model parser. It correlates those outputs by exact
canonical identity, signs the resulting runtime-facts bundle, and sends live
authenticated JSON-RPC calls through the gateway: one observed allow with graph
enforcement off and one verified strict block before upstream execution.

The infrastructure is intentionally local and modeled. It is not customer or
live-cloud evidence. Cross-source joins use exact canonical identifiers only;
mutable image tags and similar labels are never join keys.

`pinned-package.txt` is intentionally vulnerable evidence input, not an
installable project dependency. The generator materializes it as
`requirements.txt` only inside a temporary directory so the real repository
parser and package scanner execute without inviting accidental installation.
`identity-model.json` describes modeled local infrastructure only. The gateway
smoke uses process-local ephemeral stores and fixed non-secret lab tokens; it
does not require network or cloud credentials.

```bash
uv run python scripts/generate_reference_evidence_lab.py
uv run python scripts/generate_reference_evidence_lab.py --check
```

The generated proof is committed at `generated/correlation-proof.json` so the
product capture harness can pin screenshots to its manifest hash.
