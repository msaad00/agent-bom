import { describe, expect, it } from "vitest";

import { tonedChipClass, type ChipTone } from "@/lib/toned-chip";

const TONES: ChipTone[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "ok",
  "warn",
  "danger",
  "neutral",
  "accent",
];

describe("tonedChipClass", () => {
  it("emits a light-theme pair and a dark:-scoped pair for every tone", () => {
    for (const tone of TONES) {
      const cls = tonedChipClass(tone);
      // Light theme: a saturated -700 text and a -500 tinted bg (no dark: prefix).
      expect(cls).toMatch(/(?<!dark:)\btext-[a-z]+-700\b/);
      expect(cls).toMatch(/(?<!dark:)\bbg-[a-z]+-500\/\d+\b/);
      // Dark theme: restores the dark-canvas treatment.
      expect(cls).toMatch(/\bdark:bg-[a-z]+-9\d0(?:\/\d+)?\b/);
      expect(cls).toMatch(/\bdark:text-[a-z]+-200\b/);
    }
  });

  it("never leaves an unguarded dark-only pale-text token (the light-theme bug)", () => {
    for (const tone of TONES) {
      const cls = tonedChipClass(tone);
      // No bare (non-dark:) text-*-200/300 — that was the pale-on-pale defect.
      expect(cls).not.toMatch(/(?<!dark:)\btext-[a-z]+-(?:200|300)\b/);
      // No bare (non-dark:) bg-*-900/950 dark panel leaking into light theme.
      expect(cls).not.toMatch(/(?<!dark:)\bbg-[a-z]+-9\d0(?:\/\d+)?\b/);
    }
  });
});
