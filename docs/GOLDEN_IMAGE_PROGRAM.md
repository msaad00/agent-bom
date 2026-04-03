# Golden Image Program

The long-term target is not "we pin Debian digests." The target is "we ship a governed, scanned, signed, promoted runtime image family."

## Desired end state

Each public image is built from an approved promoted base and carries:

- pinned digest
- reproducible build inputs
- signed image
- provenance attestation
- SBOM attestation
- release scan evidence
- exception review history

## Image tiers

We separate image roles so the most visible public image stays the cleanest:

- `build` image: build-time dependencies and toolchain
- `runtime` image: default public CLI/runtime image
- `mcp` image: MCP server runtime
- `sse` image: remote transport runtime
- optional environment-specific images only when needed

## Promotion flow

1. ingest upstream base digest
2. build candidate hardened base
3. scan candidate base
4. run smoke tests
5. generate SBOM and provenance
6. review exceptions
7. promote approved base
8. build product images only from approved promoted bases

## Promotion gates

Each promoted base and each public product image should pass:

- native `agent-bom image`
- Container vulnerability scanner
- Docker Scout
- architecture-specific smoke tests
- package extraction sanity checks
- SBOM generation
- provenance generation

## Exception governance

Exceptions must include:

- vulnerability ID
- affected package
- image scope
- architecture scope
- reason
- owner
- opened date
- review date
- expiry date

Exceptions are temporary. If the expiry is reached, release should block until the exception is reviewed or removed.

## Rollout plan

### 30 days

- define image policy
- create exception registry
- gate releases on extraction success and unapproved `HIGH`/`CRITICAL`
- publish SBOMs consistently

### 60 days

- build approved golden bases per architecture
- add package and layer diff reports between releases
- add Docker Scout as a promotion gate

### 90 days

- sign public images
- attest SBOM and provenance
- require promoted bases for all public runtime images
- add deployment-time verification hooks
