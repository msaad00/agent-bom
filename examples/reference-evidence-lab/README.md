# Reference evidence lab

This credential-free lab executes the real project dependency parser, bundled
pinned-advisory scanner, CycloneDX loader, Kubernetes IaC scanner, MCP parser,
and a strict local identity-model parser. The generator builds modeled source
snapshots from those validated artifacts, correlates them by exact canonical
identity, signs each source receipt, and
sends live authenticated JSON-RPC calls through the gateway: one observed allow
and one explicit tool-name policy block before upstream execution. The local
call proves tool invocation; modeled identity grants do not prove provider
authentication, resource activity, or exploitability. The graph retains these
separate evidence relationships. Its modeled permission route describes potential
access to the data asset; it contains no vulnerability exploit edge or observed
cloud activity. The dependency advisory remains a separate finding.

The infrastructure is intentionally local and modeled. It is not customer or
live-cloud evidence. Cross-source joins use exact canonical identifiers only;
mutable image tags and similar labels are never join keys. Image inventory
and deployment containers remain separate occurrences. After validating that
the deployment pins the exact SBOM image digest, the lab models an explicit
container-to-package composition edge; the digest does not merge runtime
permissions. The artifact binding is recorded separately from identity joins.

`pinned-package.txt` is intentionally vulnerable evidence input, not an
installable project dependency. The generator materializes it as
`requirements.txt` only inside a temporary directory so the real repository
parser and package scanner execute without inviting accidental installation.
`identity-model.json` describes modeled local infrastructure only. The gateway
smoke uses process-local ephemeral stores and fixed non-secret lab tokens; it
does not require network or cloud credentials.

```bash
uv run --extra api python scripts/generate_reference_evidence_lab.py
uv run --extra api python scripts/generate_reference_evidence_lab.py --check
```

The generated proof is committed at `generated/correlation-proof.json` so the
product capture harness can pin screenshots to its manifest hash.

Each source receipt uses HMAC-SHA256 and is bound to the lab tenant,
correlation ID, source digest and counts, freshness policy, and run timestamp.
Production correlations use the configured runtime-facts signing key; older
unsigned runs remain readable as hash-bound legacy evidence.

To inspect an actual changed-input rescan, choose a new output directory:

```bash
uv run --extra api python scripts/generate_reference_evidence_lab.py --output-dir /tmp/reference-lab-session
```

`local-session.json` contains normal AI-BOM scan results and persisted-graph
inputs for Pillow 9.0.0 before and 10.0.1 after the change, with source IDs,
input hashes, timestamps, and explicit remaining evidence gaps. The pinned
CVE-2023-4863 advisory disappears on rescan. This does not install a package,
change a deployment, prove exploitability, or qualify live cloud access.
Existing session evidence is never overwritten. Use the saved scan and graph
records with a tenant-authenticated local control plane to inspect the same
component before and after remediation.
