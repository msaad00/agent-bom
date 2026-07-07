import { fileURLToPath } from "node:url";
import path from "node:path";

import type { StorybookConfig } from "@storybook/react-vite";

const here = path.dirname(fileURLToPath(import.meta.url));
const uiRoot = path.resolve(here, "..");

const config: StorybookConfig = {
  stories: ["../stories/**/*.stories.@(ts|tsx)"],
  addons: [],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  core: {
    disableTelemetry: true,
  },
  viteFinal: async (viteConfig) => {
    viteConfig.resolve ??= {};
    const existing = viteConfig.resolve.alias;
    const extra = [
      // Mirror the tsconfig "@/*" -> repo-root path mapping.
      { find: /^@\//, replacement: `${uiRoot}/` },
      // next/link has no meaning outside the Next runtime; use a plain anchor.
      { find: "next/link", replacement: path.resolve(here, "stubs/next-link.tsx") },
    ];
    const normalizedExisting = Array.isArray(existing)
      ? existing
      : existing
        ? Object.entries(existing).map(([find, replacement]) => ({ find, replacement }))
        : [];
    viteConfig.resolve.alias = [...extra, ...normalizedExisting];
    return viteConfig;
  },
};

export default config;
