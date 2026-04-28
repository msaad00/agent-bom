# Base image policy: node 22 LTS (sits inside ui/package.json engines: ">=20 <23").
# Digest is pinned by dependabot's daily docker job; the
# scripts/check_docker_base_policy.py CI gate accepts the
# `# pending-digest` marker for at most one day after a major bump
# so a Dockerfile change can land while dependabot catches up.
# Tracking: #1961.

# ── Stage 1: Install dependencies ─────────────────────────────────────────────
FROM node:22-bookworm-slim@sha256:d415caac2f1f77b98caaf9415c5f807e14bc8d7bdea62561ea2fef4fbd08a73c AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
# Next's webpack CSS pipeline requires lightningcss' native Linux binding.
# Some npm versions omit optional platform bindings during lockfile-driven
# installs, so pin the binding explicitly in the image. Buildx injects
# TARGETARCH automatically (amd64 / arm64) when building multi-arch — pick
# the matching prebuilt so `docker buildx --platform linux/amd64,linux/arm64`
# does not try to install the x64 binary on an arm64 stage.
ARG TARGETARCH
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) pkg="lightningcss-linux-x64-gnu@1.32.0" ;; \
      arm64) pkg="lightningcss-linux-arm64-gnu@1.32.0" ;; \
      *) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    npm install --no-save --ignore-scripts "$pkg"

# ── Stage 2: Build ────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim@sha256:d415caac2f1f77b98caaf9415c5f807e14bc8d7bdea62561ea2fef4fbd08a73c AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_API_URL=http://localhost:8422
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# ── Stage 3: Run ──────────────────────────────────────────────────────────────
FROM node:22-bookworm-slim@sha256:d415caac2f1f77b98caaf9415c5f807e14bc8d7bdea62561ea2fef4fbd08a73c AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1

# Apply latest OS security patches (fixes base-image CVEs visible in Docker Scout)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*

RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone output
COPY --from=builder --chown=nextjs:nodejs /app/public ./public
COPY --from=builder --chown=nextjs:nodejs /app/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/.next/static ./.next/static
COPY --chown=nextjs:nodejs docker-entrypoint.sh ./docker-entrypoint.sh

RUN chmod +x /app/docker-entrypoint.sh

USER nextjs

EXPOSE 3000
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD node -e "const http = require('http'); http.get('http://localhost:3000', (r) => { process.exit(r.statusCode === 200 ? 0 : 1); }).on('error', () => process.exit(1));" || exit 1

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "server.js"]
