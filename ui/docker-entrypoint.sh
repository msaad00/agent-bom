#!/bin/sh
set -eu

API_URL_JSON="$(node -p 'JSON.stringify(process.env.NEXT_PUBLIC_API_URL ?? "")')"

cat > /app/public/runtime-config.js <<EOF
window.__AGENT_BOM_CONFIG__ = Object.assign({}, window.__AGENT_BOM_CONFIG__, {
  apiUrl: ${API_URL_JSON},
});
EOF

exec "$@"
