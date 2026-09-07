import { afterEach, expect, it, vi } from "vitest";
import { api } from "@/lib/api";
import { clearCache } from "@/lib/api-cache";

afterEach(() => { vi.unstubAllGlobals(); clearCache(); });

it.each(["getCostReport", "getCostForecast", "getCostAnomalies"] as const)("%s retrieves fresh evidence on consecutive refreshes", async (method) => {
  const fetcher = vi.fn()
    .mockResolvedValueOnce({ ok: true, json: async () => ({ generation: 1 }) })
    .mockResolvedValueOnce({ ok: true, json: async () => ({ generation: 2 }) });
  vi.stubGlobal("fetch", fetcher);
  await api[method]();
  expect(await api[method]()).toEqual({ generation: 2 });
  expect(fetcher).toHaveBeenCalledTimes(2);
});
