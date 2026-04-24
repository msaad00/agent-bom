#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
usage: build-airgap-image-bundle.sh --version VERSION [--platform PLATFORM] [--output-dir DIR] [--no-verify]

Builds a portable tarball containing the public agent-bom runtime images,
checksums, and a load script for disconnected registries or clusters.

Required:
  --version VERSION        Release version or tag suffix, for example 0.81.3 or v0.81.3

Optional:
  --platform PLATFORM     Image platform to pull and archive (default: linux/amd64)
  --output-dir DIR         Directory for bundle output (default: dist/airgap)
  --no-verify             Skip cosign image signature verification

Environment:
  VERIFY_SIGNATURES=0      Same as --no-verify
USAGE
}

version=""
platform="linux/amd64"
output_dir="dist/airgap"
verify_signatures="${VERIFY_SIGNATURES:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --output-dir)
      output_dir="${2:-}"
      shift 2
      ;;
    --platform)
      platform="${2:-}"
      shift 2
      ;;
    --no-verify)
      verify_signatures=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "--version is required" >&2
  usage
  exit 2
fi

version="${version#v}"
case "$version" in
  *[!A-Za-z0-9._-]*|"")
    echo "version may only contain letters, numbers, dot, underscore, and dash" >&2
    exit 2
    ;;
esac

case "$platform" in
  *[!A-Za-z0-9._/-]*|"")
    echo "platform may only contain letters, numbers, dot, underscore, dash, and slash" >&2
    exit 2
    ;;
esac

command -v docker >/dev/null || {
  echo "docker is required" >&2
  exit 1
}

if [[ "$verify_signatures" != "0" ]]; then
  command -v cosign >/dev/null || {
    echo "cosign is required unless --no-verify or VERIFY_SIGNATURES=0 is set" >&2
    exit 1
  }
fi

safe_platform="$(printf '%s' "$platform" | tr '/:' '__')"
bundle_root="${output_dir%/}/agent-bom-airgap-${version}-${safe_platform}"
images_dir="${bundle_root}/images"
manifest_dir="${bundle_root}/manifests"
rm -rf "$bundle_root"
mkdir -p "$images_dir" "$manifest_dir"

images=(
  "agentbom/agent-bom:${version}"
  "agentbom/agent-bom-ui:${version}"
)

identity_regexp='https://github.com/msaad00/agent-bom/.github/workflows/release.yml@.*'

for image in "${images[@]}"; do
  echo "Pulling ${image} for ${platform}"
  docker pull --platform "$platform" "$image"

  if [[ "$verify_signatures" != "0" ]]; then
    echo "Verifying ${image} signature"
    cosign verify "$image" \
      --certificate-oidc-issuer https://token.actions.githubusercontent.com \
      --certificate-identity-regexp "$identity_regexp" \
      >/dev/null
  fi

  safe_name="$(printf '%s' "$image" | tr '/:' '__')"
  tar_path="${images_dir}/${safe_name}.tar"
  docker save "$image" -o "$tar_path"
  printf '%s\n' "$image" >> "${manifest_dir}/images.txt"
done

(
  cd "$bundle_root"
  find images -type f -name '*.tar' -print0 | sort -z | xargs -0 sha256sum > manifests/sha256sums.txt
)

cat > "${bundle_root}/load-images.sh" <<'LOAD'
#!/usr/bin/env bash
set -euo pipefail

bundle_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$bundle_dir"
sha256sum -c manifests/sha256sums.txt
find images -type f -name '*.tar' -print0 | sort -z | while IFS= read -r -d '' image_tar; do
  docker load -i "$image_tar"
done
LOAD
chmod +x "${bundle_root}/load-images.sh"

cat > "${bundle_root}/README.md" <<README
# agent-bom air-gapped image bundle ${version}

Contents:

- platform: \`${platform}\`
- \`images/*.tar\`: Docker image archives for \`agentbom/agent-bom:${version}\` and \`agentbom/agent-bom-ui:${version}\`
- \`manifests/images.txt\`: source image references
- \`manifests/sha256sums.txt\`: archive checksums
- \`load-images.sh\`: checksum verification and \`docker load\`

Load on the disconnected host:

\`\`\`bash
tar -xzf agent-bom-airgap-${version}-${safe_platform}.tar.gz
cd agent-bom-airgap-${version}-${safe_platform}
./load-images.sh
\`\`\`
README

(
  cd "${output_dir%/}"
  tar -czf "agent-bom-airgap-${version}-${safe_platform}.tar.gz" "agent-bom-airgap-${version}-${safe_platform}"
)

echo "Wrote ${output_dir%/}/agent-bom-airgap-${version}-${safe_platform}.tar.gz"
