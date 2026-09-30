/** Local input checks mirror the supported OTLP and flat-span containers. */
export const MAX_TRACE_PREVIEW_BYTES = 10 * 1024 * 1024;

const object = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === "object" && !Array.isArray(value);
const objects = (value: unknown): value is Record<string, unknown>[] =>
  Array.isArray(value) && value.every(object);

export function parseTraceInput(text: string): Record<string, unknown> {
  if (new TextEncoder().encode(text).byteLength > MAX_TRACE_PREVIEW_BYTES) {
    throw new Error("Trace input exceeds the 10 MB browser limit.");
  }
  let value: unknown;
  try { value = JSON.parse(text); }
  catch { throw new Error("Trace input must be valid JSON. No payload was submitted."); }
  const invalid = () => new Error("Use an OTLP resourceSpans object or a flat spans object with arrays of span objects.");
  if (!object(value) || !("resourceSpans" in value || "spans" in value)) throw invalid();
  if ("spans" in value && !objects(value.spans)) throw invalid();
  if ("resourceSpans" in value) {
    if (!objects(value.resourceSpans)) throw invalid();
    for (const resource of value.resourceSpans) {
      if (!("scopeSpans" in resource)) continue;
      if (!objects(resource.scopeSpans)) throw invalid();
      for (const scope of resource.scopeSpans) {
        if ("spans" in scope && !objects(scope.spans)) throw invalid();
      }
    }
  }
  return value;
}
