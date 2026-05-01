import { defineConfig, devices } from "@playwright/test";

const PORT = 3001;
const baseURL = `http://127.0.0.1:${PORT}`;
const serverCommand =
  `if test -f .next/standalone/server.js && test -f .next/standalone/.next/server/pages-manifest.json; ` +
  `then HOSTNAME=127.0.0.1 PORT=${PORT} node .next/standalone/server.js; ` +
  `else npm run dev -- --hostname 127.0.0.1 --port ${PORT}; fi`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  use: {
    baseURL,
    trace: "on-first-retry",
  },
  webServer: {
    command: serverCommand,
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      NEXT_PUBLIC_API_URL: "",
      NEXT_TELEMETRY_DISABLED: "1",
    },
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
});
