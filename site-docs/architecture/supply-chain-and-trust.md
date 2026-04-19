# Supply Chain and Trust

`agent-bom` keeps its dependency and release trust controls explicit:

- bounded runtime dependency ranges
- locked Python and UI dependency resolution
- extras-specific audit coverage
- parser fuzzing for untrusted ingest surfaces
- signed and attested release artifacts
- published self-SBOMs

## Dependency model

There are three important layers:

1. runtime dependency policy in `pyproject.toml`
2. exact Python resolution in `uv.lock`
3. exact UI resolution in `ui/package-lock.json`

The default install stays lean. Heavier surfaces are behind extras such as:

- `api`
- `mcp-server`
- `graph`
- `cloud`
- `dashboard`
- `postgres`
- `oidc`

That keeps the base scanner smaller while making deployment-specific dependency
surfaces explicit.

## Extras audit coverage

Optional extras pull in additional transitive packages, so they are audited as
deployment surfaces instead of being treated as invisible add-ons.

The extras audit workflow runs for grouped surfaces such as:

- `api-runtime`
- `mcp-surface`
- `analytics-ui`
- `cloud-surface`

It captures:

- resolved dependency trees
- `pip-audit` JSON results

This complements the default dependency review workflow rather than replacing
it.

## Parser and fuzz coverage

High-risk ingest surfaces are fuzzed because they accept external data:

- policy ingest
- SBOM ingest
- skill/instruction parsing
- external scanner JSON ingest

The external scanner fuzz target covers:

- CVE-scanner JSON reports (common industry formats)
- container-SBOM JSON reports (common industry formats)
- auto-detection of scanner formats

## Release trust

Tagged releases publish:

- Python distribution files
- Sigstore bundles (`*.sigstore.json`)
- SLSA provenance bundles (`*.intoto.jsonl`)
- CycloneDX self-SBOMs

The repository documentation includes a release verification guide with:

- `cosign verify-blob` examples
- provenance inspection
- self-SBOM inspection and rescanning

## Related docs

- [Data Ingestion and Security](data-ingestion-and-security.md)
- [Runtime Proxy](../features/runtime-proxy.md)
- [Security Policy](../security.md)
