# Air-Gapped Image Bundle

Use this workflow when a customer must import release images into a disconnected
registry or cluster. The bundle contains the API/runtime image, the UI image,
checksums, and a loader script. Bundles are platform-specific; produce one for
`linux/amd64` and another for `linux/arm64` when your disconnected estate runs
both architectures.

## Build A Bundle

From an internet-connected build host:

```bash
scripts/release/build-airgap-image-bundle.sh \
  --version 0.81.3 \
  --platform linux/amd64 \
  --output-dir dist/airgap
```

The script:

1. pulls `agentbom/agent-bom:<version>` and `agentbom/agent-bom-ui:<version>` for the requested platform
2. verifies image signatures with cosign by default
3. saves both images as Docker archives
4. writes `manifests/images.txt`
5. writes `manifests/sha256sums.txt`
6. packages everything as `agent-bom-airgap-<version>.tar.gz`

If your build host cannot install cosign, use `--no-verify` only after
verifying the release through `docs/RELEASE_VERIFICATION.md` on a trusted
machine.

## Import On The Disconnected Host

```bash
tar -xzf agent-bom-airgap-0.81.3-linux_amd64.tar.gz
cd agent-bom-airgap-0.81.3-linux_amd64
./load-images.sh
```

The loader verifies archive checksums before running `docker load`.

## Push To An Internal Registry

```bash
VERSION=0.81.3
REGISTRY=registry.internal.example.com/security

docker tag "agentbom/agent-bom:${VERSION}" "${REGISTRY}/agent-bom:${VERSION}"
docker tag "agentbom/agent-bom-ui:${VERSION}" "${REGISTRY}/agent-bom-ui:${VERSION}"

docker push "${REGISTRY}/agent-bom:${VERSION}"
docker push "${REGISTRY}/agent-bom-ui:${VERSION}"
```

Then point Helm at the internal registry:

```yaml
image:
  repository: registry.internal.example.com/security/agent-bom
  tag: "0.81.3"

controlPlane:
  ui:
    image:
      repository: registry.internal.example.com/security/agent-bom-ui
      tag: "0.81.3"
```

## GitHub Actions Bundle Job

Maintainers can also generate the same artifact from GitHub Actions through
the manual "Air-gapped image bundle" workflow. Choose `linux/amd64` or
`linux/arm64` explicitly. Treat the uploaded artifact as a transfer package;
the receiving environment should still verify checksums after download and
before import.

## Audit Record

For regulated imports, retain:

- source release tag and commit SHA
- output of `cosign verify` for both images
- `manifests/images.txt`
- `manifests/sha256sums.txt`
- internal registry digest after push
- operator, approver, import time, and target environment
