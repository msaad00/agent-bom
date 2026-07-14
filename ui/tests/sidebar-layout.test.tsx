import { describe, expect, it } from "vitest";

import { mainContentPaddingClass } from "@/components/sidebar-layout";

describe("mainContentPaddingClass", () => {
  it("reserves the rail width when collapsed and the full sidebar when expanded", () => {
    expect(mainContentPaddingClass(true)).toBe("lg:pl-[52px]");
    expect(mainContentPaddingClass(false)).toBe("lg:pl-[240px]");
  });
});
