import { describe, expect, it } from "vitest";

import {
  GENERIC_ERROR_MESSAGE,
  NETWORK_ERROR_MESSAGE,
  NOT_FOUND_ERROR_MESSAGE,
  PERMISSION_ERROR_MESSAGE,
  errorBoundaryMessage,
  errorReference,
} from "@/lib/error-boundary-message";

describe("errorBoundaryMessage", () => {
  it("never returns the raw exception text", () => {
    const secret = "connection failed: postgresql://user:hunter2@db.internal:5432/agent_bom";

    const shown = errorBoundaryMessage(new Error(secret));

    expect(shown).not.toContain("hunter2");
    expect(shown).not.toContain("db.internal");
    expect(shown).toBe(GENERIC_ERROR_MESSAGE);
  });

  it("does not leak the demo capture's raw message", () => {
    expect(errorBoundaryMessage(new Error("Invalid time value"))).toBe(GENERIC_ERROR_MESSAGE);
  });

  it("recognizes an unreachable control plane", () => {
    expect(errorBoundaryMessage(new Error("Failed to fetch"))).toBe(NETWORK_ERROR_MESSAGE);
    expect(errorBoundaryMessage(new Error("NetworkError when attempting to fetch resource"))).toBe(NETWORK_ERROR_MESSAGE);
  });

  it("recognizes an authorization failure", () => {
    expect(errorBoundaryMessage(new Error("Request failed with status 403"))).toBe(PERMISSION_ERROR_MESSAGE);
    expect(errorBoundaryMessage(new Error("Unauthorized"))).toBe(PERMISSION_ERROR_MESSAGE);
  });

  it("recognizes a missing resource", () => {
    expect(errorBoundaryMessage(new Error("404 Not Found"))).toBe(NOT_FOUND_ERROR_MESSAGE);
  });

  it("handles non-Error values without throwing", () => {
    expect(errorBoundaryMessage(undefined)).toBe(GENERIC_ERROR_MESSAGE);
    expect(errorBoundaryMessage("some string")).toBe(GENERIC_ERROR_MESSAGE);
    expect(errorBoundaryMessage({ nope: true })).toBe(GENERIC_ERROR_MESSAGE);
  });

  it("returns only the documented catalog entries", () => {
    const catalog = new Set([
      GENERIC_ERROR_MESSAGE,
      NETWORK_ERROR_MESSAGE,
      PERMISSION_ERROR_MESSAGE,
      NOT_FOUND_ERROR_MESSAGE,
    ]);
    const probes = ["boom", "500 server error", "TypeError: x is not a function", "403", "Failed to fetch", ""];

    for (const probe of probes) {
      expect(catalog.has(errorBoundaryMessage(new Error(probe)))).toBe(true);
    }
  });
});

describe("errorReference", () => {
  it("exposes a short digest a user can quote", () => {
    expect(errorReference("abcdef0123456789abcdef")).toBe("abcdef012345");
  });

  it("returns null when there is no digest", () => {
    expect(errorReference(undefined)).toBeNull();
    expect(errorReference("   ")).toBeNull();
  });

  it("rejects a caller-controlled value that is not a digest", () => {
    expect(errorReference("postgresql://user:secret@db.internal")).toBeNull();
    expect(errorReference("raw error message")).toBeNull();
  });
});
