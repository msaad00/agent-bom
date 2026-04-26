import "@testing-library/jest-dom";
import { afterEach } from "vitest";

import { clearCache } from "../lib/api-cache";

afterEach(() => {
  delete window.__AGENT_BOM_CONFIG__;
  // Clear the in-memory API cache between tests so a previous test's
  // cached GET response cannot satisfy a subsequent test's mocked fetch.
  clearCache();
});
