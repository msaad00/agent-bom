# Supply Chain and Dependency Controls

`agent-bom` keeps its dependency and release trust posture explicit:

- small required runtime footprint
- optional extras for heavier surfaces
- locked dependency resolution
- per-PR dependency review
- signed and attested release artifacts
- published self-SBOMs
- self-scan and fuzz coverage in CI

This page is the operator-facing map of those controls.

## Dependency model

There are three layers to understand:

1. Core runtime dependencies in [pyproject.toml](../pyproject.toml)
2. Fully resolved Python dependencies in [uv.lock](../uv.lock)
3. Fully resolved UI dependencies in [ui/package-lock.json](../ui/package-lock.json)

The core runtime stays intentionally small. Heavier surfaces are behind extras
such as:

- `api`
- `mcp-server`
- `graph`
- `cloud`
- `dashboard`
- `postgres`
- `oidc`

That keeps the default install lean while still allowing fuller deployments to
turn on additional capability explicitly.

Some extras also carry platform markers where an upstream provider package is
not yet compatible with the full supported Python/platform matrix. Those
constraints are intentional and documented rather than hidden.

## Version control and drift boundaries

`agent-bom` uses bounded runtime version ranges in `pyproject.toml` and locked
resolution in `uv.lock`.

That gives two protections:

- maintainers and CI get exact, reproducible transitive resolution
- users installing without the lockfile still stay inside known-compatible major
  ranges instead of drifting arbitrarily

Transitive security pins that close specific advisories are annotated inline
with GHSA/CVE context in `pyproject.toml`.

## Extras audit coverage

The root dependency graph is not the only surface that matters. Optional extras
pull in additional transitive dependencies, so they need independent visibility.

The extras audit workflow is:

- workflow: [extras-audit.yml](../.github/workflows/extras-audit.yml)
- trigger: pull requests touching dependency surfaces, weekly schedule, or
  manual dispatch
- output: per-surface dependency trees and `pip-audit` JSON artifacts

Current audit groups:

- `api-runtime`
- `mcp-surface`
- `analytics-ui`
- `cloud-surface`

Those groups are intentionally broader than a single extra so the artifacts map
to real deployment surfaces rather than individual package toggles.

## CI and scanning controls

Dependency and supply-chain controls are enforced through multiple workflows:

- `dependency-review.yml` for per-PR dependency diffs
- `dependency-submission.yml` for GitHub dependency graph visibility
- `dependency-pin-check.yml` for transitive security pin discipline
- `cve-freshness.yml` for daily dependency vulnerability checks
- `container-rescan.yml` for image rescans
- `cflite-pr.yml` for parser and ingestion fuzzing
- `post-merge-self-scan.yml` for dogfooding scans against `agent-bom` itself
- `release.yml` and `publish-mcp.yml` for signed, attested release output

This is additive by design. No single workflow is treated as the entire trust
story.

## Parser and fuzz coverage

High-risk ingestion surfaces are fuzzed because they process untrusted external
data:

- `fuzz/fuzz_policy.py`
- `fuzz/fuzz_sbom.py`
- `fuzz/fuzz_skill_parser.py`
- `fuzz/fuzz_external_scanners.py`

The external scanner fuzz target covers:

- CVE-scanner JSON ingestion (common industry formats)
- container-SBOM JSON ingestion (common industry formats)
- format auto-detection via `detect_and_parse()`

That keeps the import path for third-party scanner results under the same
hardening discipline as SBOM and policy ingest.

## Release verification and SBOMs

Tagged releases publish:

- Python distributions
- Sigstore bundles (`*.sigstore.json`)
- SLSA provenance bundles (`*.intoto.jsonl`)
- CycloneDX self-SBOM (`agent-bom-sbom.cdx.json`)

Use the release verification guide:

- [Release Verification](RELEASE_VERIFICATION.md)

That document includes:

- `cosign verify-blob` examples
- provenance inspection
- self-SBOM inspection and rescanning

This is the public verification path. Release trust is not hidden inside CI.

## Where to inspect the current posture

- [Security Policy](../SECURITY.md)
- [Security Architecture](SECURITY_ARCHITECTURE.md)
- [Image Security](IMAGE_SECURITY.md)
- [Threat Model](THREAT_MODEL.md)
- [Release Verification](RELEASE_VERIFICATION.md)
- [Permissions and Trust](PERMISSIONS.md)

## Operational guidance

For maintainers:

- keep runtime dependency ranges bounded
- refresh `uv.lock` whenever dependency policy changes
- review extras audit artifacts, not just the default environment
- treat parser fuzz coverage as part of release trust, not optional polish

For operators:

- verify release assets before internal distribution
- archive the published self-SBOM with the release artifact set
- use the same release verification process for both PyPI and GitHub release
  consumption
