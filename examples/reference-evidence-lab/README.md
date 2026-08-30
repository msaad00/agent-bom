# Reference evidence lab

This credential-free lab exercises the real project dependency parser and the
bundled, pinned advisory scanner, then correlates that output with an exact OCI
digest/SBOM, modeled Kubernetes resources, MCP configuration, provider identity,
and runtime gateway evidence.

The infrastructure is intentionally local and modeled. It is not customer or
live-cloud evidence. Cross-source joins use exact canonical identifiers only;
mutable image tags and similar labels are never join keys.

`pinned-package.txt` is intentionally vulnerable evidence input, not an
installable project dependency. The generator materializes it as
`requirements.txt` only inside a temporary directory so the real repository
parser and package scanner execute without inviting accidental installation.

```bash
uv run python scripts/generate_reference_evidence_lab.py
uv run python scripts/generate_reference_evidence_lab.py --check
```

The generated proof is committed at `generated/correlation-proof.json` so the
product capture harness can pin screenshots to its manifest hash.
