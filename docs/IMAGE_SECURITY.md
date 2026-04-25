# Image Security

`agent-bom` release images are treated as governed security artifacts, not just build outputs.

## Release policy

Every public runtime image must:

- use a pinned base image digest
- build reproducibly from versioned source
- pass smoke tests
- generate SBOM attestations
- pass native `agent-bom image` extraction and vulnerability scanning
- pass external image validation gates
- document any temporary CVE exception with an owner and expiry

## Current release gates

The release pipeline currently enforces:

- `agent-bom` self-scan gate
- Container image scan gate
- Docker image smoke test
- SBOM generation
- Sigstore signing for Python distributions
- Docker provenance and SBOM attestations

Relevant workflows:

- `.github/workflows/release.yml`
- `.github/workflows/container-rescan.yml`

## Exception policy

Temporary exceptions are allowed only when all of the following are true:

1. the vulnerability is inherited from the runtime base or an unavoidable transitive dependency
2. no patched version is available in the supported upstream lineage
3. the exception is documented with owner, reason, review date, and expiry
4. the exception is revisited on every base refresh and release

Active image exceptions are tracked in [`security/image-exceptions.yaml`](../security/image-exceptions.yaml).

The generated image ignore file remains the scanner input today, but the YAML registry is the human-reviewed source of truth for why an exception exists.

Current no-fix medium findings may remain visible in Docker Scout until the
upstream base image publishes patched packages. They must still have structured
exceptions with short review windows, and release operators should remove the
matching `.trivyignore` entries as soon as a fixed base digest or safe package
upgrade is available.

## Stable release bar

The target for a "most stable" public release is:

- no unresolved public `CRITICAL` vulnerabilities in the default runtime image
- no unresolved public `HIGH` vulnerabilities with a known fix
- no image release when native package extraction fails
- no release when image scan results differ materially across supported architectures without explanation

If a public image still carries an unresolved `CRITICAL`, the release is not treated as a clean security release even if the risk is documented.

## Multi-arch requirements

Every supported architecture must be validated independently:

- `linux/amd64`
- `linux/arm64`

For each architecture we want:

- identical release policy
- independent image scan results
- independent SBOM and provenance
- parity review for package drift and CVE drift

## Near-term follow-ups

- add a generated sync step from `security/image-exceptions.yaml` into the image scanner ignore file
- sign and attest Docker images directly, not just Python artifacts and BuildKit attestations
- add Docker Scout as an explicit release gate
- add promoted golden base images per architecture
