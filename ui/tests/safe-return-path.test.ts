import { describe, expect, it } from "vitest";

import { safeReturnPath } from "@/lib/safe-return-path";

describe("safeReturnPath", () => {
  it("allows normal in-app paths", () => {
    expect(safeReturnPath("/connections")).toBe("/connections");
    expect(safeReturnPath("/findings?severity=critical")).toBe("/findings?severity=critical");
  });

  it("rejects protocol-relative and off-site open redirects", () => {
    expect(safeReturnPath("//evil.example/phish")).toBe("/");
    expect(safeReturnPath("https://evil.example/phish")).toBe("/");
    expect(safeReturnPath(null)).toBe("/");
    expect(safeReturnPath("")).toBe("/");
  });

  it("rejects login loops and backslash tricks", () => {
    expect(safeReturnPath("/login")).toBe("/");
    expect(safeReturnPath("/login?returnTo=%2F")).toBe("/");
    expect(safeReturnPath("/\\evil.example")).toBe("/");
  });
});
