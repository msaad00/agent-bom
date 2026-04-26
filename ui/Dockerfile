# ── Stage 1: Install dependencies ─────────────────────────────────────────────
FROM node:25-slim@sha256:e49fd70491eb042270f974167c874d6245287263ffc16422fcf93b3c150409d8 AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --ignore-scripts
# Next's webpack CSS pipeline requires lightningcss' native Linux binding.
# Some npm versions omit optional platform bindings during lockfile-driven
# installs, so pin the Linux binding in the image rather than relying on host
# lockfile resolution behavior.
RUN npm install --no-save --ignore-scripts lightningcss-linux-x64-gnu@1.32.0

# ── Stage 2: Build ────────────────────────────────────────────────────────────
FROM node:25-slim@sha256:e49fd70491eb042270f974167c874d6245287263ffc16422fcf93b3c150409d8 AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .

ARG NEXT_PUBLIC_API_URL=http://localhost:8422
ENV NEXT_PUBLIC_API_URL=$NEXT_PUBLIC_API_URL
ENV NEXT_TELEMETRY_DISABLED=1

RUN npm run build

# ── Stage 3: Run ──────────────────────────────────────────────────────────────
FROM node:25-slim@sha256:e49fd70491eb042270f974167c874d6245287263ffc16422fcf93b3c150409d8 AS runner
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
