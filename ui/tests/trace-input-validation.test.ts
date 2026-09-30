import { describe, expect, it } from "vitest";
import { MAX_TRACE_PREVIEW_BYTES, parseTraceInput } from "@/lib/trace-intake";

describe("trace input formats and bounds", () => {
  it.each([{ spans: [] }, { spans: [{ name: "tool_call" }] }, { resourceSpans: [{ scopeSpans: [{ spans: [{}] }] }] }])("accepts supported containers", (value) => {
    expect(parseTraceInput(JSON.stringify(value))).toEqual(value);
  });
  it.each([null, {}, { spans: [null] }, { resourceSpans: [{ scopeSpans: {} }] }, { resourceSpans: [{ scopeSpans: [{ spans: [7] }] }] }])("rejects malformed containers", (value) => {
    expect(() => parseTraceInput(JSON.stringify(value))).toThrow();
  });
  it("bounds UTF-8 bytes for pasted input", () => {
    const text = JSON.stringify({ spans: [], note: "界".repeat(MAX_TRACE_PREVIEW_BYTES / 3) });
    expect(text.length).toBeLessThan(MAX_TRACE_PREVIEW_BYTES);
    expect(() => parseTraceInput(text)).toThrow("10 MB");
  });
});
